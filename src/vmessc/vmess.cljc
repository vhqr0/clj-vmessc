(ns vmessc.vmess
  (:require [clj-bytes.core :as b]
            [clj-bytes.struct :as st]
            [clojure.string :as str]
            [vmessc.sys :as sys]
            [vmessc.crypto :as crypto]
            [vmessc.protocols :as proto]))

;;; kdf

(def kdf-1-label
  "Vmess kdf first level label."
  "VMess AEAD KDF")

(def kdf-2-labels
  "Vmess kdf second level labels."
  {:aid          "AES Auth ID Encryption"
   :req-len-key  "VMess Header AEAD Key_Length"
   :req-len-iv   "VMess Header AEAD Nonce_Length"
   :req-key      "VMess Header AEAD Key"
   :req-iv       "VMess Header AEAD Nonce"
   :resp-len-key "AEAD Resp Header Len Key"
   :resp-len-iv  "AEAD Resp Header Len IV"
   :resp-key     "AEAD Resp Header Key"
   :resp-iv      "AEAD Resp Header IV"})

(def kdf-1-vd
  "Vmess kdf first level digest state."
  (-> (crypto/->sha256-vd)
      (crypto/->recur-vd (b/of-str kdf-1-label))))

(def kdf-2-vds
  "Vmess kdf second level digest states."
  (->> kdf-2-labels
       (map
        (fn [[k l]]
          (let [vd (-> kdf-1-vd (crypto/->recur-vd (b/of-str l)))]
            [k vd])))
       (into {})))

(defn kdf
  "Vmess kdf digest."
  [type b & labels]
  {:pre [(contains? kdf-2-vds type)]}
  (let [vd (->> labels
                (reduce
                 (fn [vd ^bytes label]
                   (-> vd (crypto/->recur-vd label)))
                 (crypto/vd-clone (get kdf-2-vds type))))]
    (crypto/vd-digest! vd b)))

;;; id

(def vmess-uuid
  "Vmess uuid."
  "c48619fe-8f02-49e0-b9e9-edf763e17e21")

(defn uuid->bytes
  "Convert uuid to bytes."
  [uuid]
  (b/of-hex (str/replace (str uuid) "-" "")))

(defn ->id
  "Construct expanded vmess id from uuid."
  [uuid]
  (let [cmd-key (crypto/md5 (b/concat! (uuid->bytes uuid) (b/of-str vmess-uuid)))
        auth-key (-> (kdf :aid cmd-key) (b/sub! 0 16))]
    {:uuid uuid :cmd-key cmd-key :auth-key auth-key}))

(comment
  (->id (random-uuid)))

(def st-aid
  "Struct of vmess auth id."
  (st/tuple
   st/int64-be
   (st/bytes-fixed 4)))

(defn ->auth-param
  "Construct vmess auth param."
  []
  {:now (sys/now) :nonce (b/rand 4)})

(defn ->aid
  "Convert auth param to aid bytes."
  [{:keys [now nonce]}]
  (let [now-sec (int (/ (inst-ms now) 1000.0))
        aid (-> [now-sec nonce] (st/pack st-aid))
        crc32 (-> (crypto/crc32 aid) (st/pack st/uint32-be))]
    (b/concat! aid crc32)))

(defn ->eaid
  "Construct vmess eaid."
  ([id]
   (->eaid id (->auth-param)))
  ([{:keys [auth-key]} param]
   (let [aid (->aid param)]
     (crypto/aes128-ecb-encrypt auth-key aid))))

(comment
  (-> (random-uuid) ->id ->eaid))

;;; param

(defn ->param
  "Construct vmess connection param."
  [id addr]
  (let [key (b/rand 16) iv (b/rand 16)]
    {:id id
     :addr addr
     :key key
     :iv iv
     :rkey (-> (crypto/sha256 key) (b/sub! 0 16))
     :riv (-> (crypto/sha256 iv) (b/sub! 0 16))
     :nonce (b/rand 8)
     :verify (rand-int 256)
     :pad (b/rand (rand-int 16))}))

(comment
  (-> (->id (random-uuid)) (->param ["www.google.com" 80])))

(defn len-masks-seq
  "Generate seq of len masks."
  [b]
  (let [r (crypto/shake128-reader b)]
    (repeatedly #(-> (r 2) (st/unpack-one st/uint16-be)))))

(defn ivs-seq
  "Generate seq of crypt ivs."
  ([iv]
   (ivs-seq iv 0))
  ([iv cnt]
   (lazy-seq
    (cons
     (b/concat! (st/pack cnt st/uint16-be) iv)
     (ivs-seq iv (inc cnt))))))

(defn ->crypt-state
  "Construct base crypt state."
  [key iv param]
  {:key (crypto/->aes-key key)
   :ivs (ivs-seq (b/sub! iv 2 12))
   :len-masks (len-masks-seq iv)
   :param param})

(comment
  (->> (len-masks-seq (b/rand 16)) (take 10))
  (->> (ivs-seq (b/rand 12)) (take 10) (map b/hex)))

;;; encrypt

(defn ->encrypt-state
  "Construct encrypt state."
  [{:keys [key iv] :as param}]
  (merge
   (->crypt-state key iv param)
   {:stage :wait-first-frame}))

(defmulti advance-encrypt-state
  "Update encrypt state, return encrypted bytes and new state."
  (fn [state _b] (:stage state)))

(def st-req
  "Struct of vmess request."
  (st/keys
   :ver st/uint8
   :iv (st/bytes-fixed 16)
   :key (st/bytes-fixed 16)
   :verify st/uint8
   :opt st/uint8
   :pad-sec (st/bits [4 4])
   :rsv st/uint8
   :cmd st/uint8
   :port st/uint16-be
   :atype st/uint8
   :host (-> (st/bytes-var st/uint8) st/wrap-str)))

(defn ->req
  "Construct vmess request."
  [{:keys [addr iv key verify pad]}]
  (let [req (-> {:ver 1
                 :iv iv
                 :key key
                 :verify verify
                 :opt 5 ; M|S
                 :pad-sec [(b/count pad) 3] ; AESGCM
                 :rsv 0
                 :cmd 1 ; TCP
                 :port (second addr)
                 :atype 2 ; domain name
                 :host (first addr)}
                (st/pack st-req)
                (b/concat! pad))
        fnv1a (-> (crypto/fnv1a req) (st/pack st/uint32-be))]
    (b/concat! req fnv1a)))

(comment
  (-> (->id (random-uuid)) (->param ["www.google.com" 80]) ->req))

(defmethod advance-encrypt-state :wait-first-frame [state b]
  (let [{:keys [param]} state
        {:keys [id nonce]} param
        {:keys [cmd-key]} id
        eaid (->eaid id)
        req (->req param)
        len (-> (b/count req) (st/pack st/uint16-be))
        elen (let [key (-> (kdf :req-len-key cmd-key eaid nonce) (b/sub! 0 16))
                   iv (-> (kdf :req-len-iv cmd-key eaid nonce) (b/sub! 0 12))]
               (crypto/aes128-gcm-encrypt key iv len eaid))
        ereq (let [key (-> (kdf :req-key cmd-key eaid nonce) (b/sub! 0 16))
                   iv (-> (kdf :req-iv cmd-key eaid nonce) (b/sub! 0 12))]
               (crypto/aes128-gcm-encrypt key iv req eaid))
        [eb state] (-> state
                       (assoc :stage :wait-frame)
                       (advance-encrypt-state b))]
    [(b/concat! eaid elen nonce ereq eb) state]))

(defmethod advance-encrypt-state :wait-frame [state b]
  (let [{:keys [key ivs len-masks]} state
        eb (crypto/aes128-gcm-encrypt key (first ivs) b (b/empty))
        elen (-> (b/count eb) (bit-xor (first len-masks)) (st/pack st/uint16-be))]
    [(b/concat! elen eb)
     (-> state
         (update :ivs rest)
         (update :len-masks rest))]))

(defn ->encrypt-xform
  "Construct vmess encrypt trans function for async chan."
  [state]
  (let [vstate (volatile! state)]
    (fn [rf]
      (fn
        ([] (rf))
        ([result] (rf result))
        ([result input]
         (let [[b state] (advance-encrypt-state @vstate input)]
           (vreset! vstate state)
           (rf result b)))))))

;;; cryptor

(defn ->decrypt-state
  "Construct decrypt state."
  [{:keys [rkey riv] :as param}]
  (merge
   (->crypt-state rkey riv param)
   {:stage :wait-resp-len
    :buffer (b/empty)}))

(defmulti advance-decrypt-state
  "Update decrypt state, return decrypted bytes (or nil) and new state."
  (fn [state] (:stage state)))

(defmethod advance-decrypt-state :wait-resp-len [state]
  (let [{:keys [buffer param]} state
        {:keys [rkey riv]} param]
    (if (< (b/count buffer) 18)
      [nil state]
      (let [[elen buffer] (b/split-at! 18 buffer)
            key (-> (kdf :resp-len-key rkey) (b/sub! 0 16))
            iv (-> (kdf :resp-len-iv riv) (b/sub! 0 12))
            len (-> (crypto/aes128-gcm-decrypt key iv elen (b/empty))
                    (st/unpack-one st/uint16-be))]
        (-> state
            ;; assoc encrypted req len
            (assoc :stage :wait-resp :buffer buffer :len (+ len 16))
            advance-decrypt-state)))))

(def st-resp
  "Struct of vmess response."
  (st/keys
   :verify st/uint8
   :opt st/uint8
   :cmd st/uint8
   :data (st/bytes-var st/uint8)))

(defmethod advance-decrypt-state :wait-resp [state]
  (let [{:keys [param buffer len]} state
        {:keys [rkey riv verify]} param]
    (if (< (b/count buffer) len)
      [nil state]
      (let [[eresp buffer] (b/split-at! len buffer)
            key (-> (kdf :resp-key rkey) (b/sub! 0 16))
            iv (-> (kdf :resp-iv riv) (b/sub! 0 12))
            resp (-> (crypto/aes128-gcm-decrypt key iv eresp (b/empty))
                     (st/unpack-one st-resp))]
        (if-not (= verify (:verify resp))
          (throw (ex-info "verify vmess resp failed" {}))
          (-> state
              (assoc :stage :wait-frame-len :buffer buffer)
              advance-decrypt-state))))))

(defn decrypt-len
  "Decrypt len, assoc decrypted len in state."
  [state len]
  (let [{:keys [len-masks]} state]
    (-> state
        (assoc :len (-> len (st/unpack-one st/uint16-be) (bit-xor (first len-masks))))
        (update :len-masks rest))))

(defmethod advance-decrypt-state :wait-frame-len [state]
  (let [{:keys [buffer]} state]
    (if (< (b/count buffer) 2)
      [nil state]
      (let [[len buffer] (b/split-at! 2 buffer)]
        (-> state
            (assoc :stage :wait-frame :buffer buffer)
            (decrypt-len len)
            advance-decrypt-state)))))

(defmethod advance-decrypt-state :wait-frame [state]
  (let [{:keys [key ivs buffer len]} state]
    (if (< (b/count buffer) len)
      [nil state]
      (let [[eb buffer] (b/split-at! len buffer)
            iv (first ivs)
            b (crypto/aes128-gcm-decrypt key iv eb (b/empty))
            stage (if (b/empty? b) :closed :wait-frame-len)
            [nb state] (-> state
                           (assoc :stage stage :buffer buffer)
                           advance-decrypt-state)
            b (cond-> b
                (some? nb) (b/concat! nb))]
        [b state]))))

(defmethod advance-decrypt-state :closed [state]
  (if-not (b/empty? (:buffer state))
    (throw (ex-info "invalid data after vmess connection closed" {}))
    [nil state]))

(defn ->decrypt-xform
  "Construct vmess decrypt trans function for async chan."
  [state]
  (let [vstate (volatile! state)]
    (fn [rf]
      (fn
        ([] (rf))
        ([result]
         (if (= (:stage @vstate) :closed)
           (rf result)
           (throw (ex-info "invalid shutdown before vmess connection closed" {:stage (:stage @vstate)}))))
        ([result input]
         (vswap! vstate update :buffer b/concat! input)
         (let [[b state] (advance-decrypt-state @vstate)]
           (vreset! vstate state)
           (when (some? b)
             (rf result b))))))))

;;; connect

(defn ->xform-pair
  "Construct vmess xform pair."
  [param]
  [(->decrypt-xform (->decrypt-state param))
   (->encrypt-xform (->encrypt-state param))])

(defmethod proto/->proxy-connect-info :vmess [{:keys [addr]} {:keys [id net-opts]}]
  (let [param (->param id addr)]
    {:net-opts net-opts :xform-pair (->xform-pair param)}))
