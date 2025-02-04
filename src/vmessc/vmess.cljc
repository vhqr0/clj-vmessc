(ns vmessc.vmess
  (:require [clj-bytes.core :as b]
            [clj-bytes.struct :as st]
            [clojure.string :as str]
            [vmessc.crypto :as crypto]
            [vmessc.protocols :as proto]))

;;; kdf

(def kdf-base-label
  "Vmess kdf base label."
  "VMess AEAD KDF")

(def kdf-labels
  "Vmess kdf labels."
  {:aid "AES Auth ID Encryption"
   :req-len-key "VMess Header AEAD Key_Length"
   :req-len-iv "VMess Header AEAD Nonce_Length"
   :req-key "VMess Header AEAD Key"
   :req-iv "VMess Header AEAD Nonce"
   :resp-len-key "AEAD Resp Header Len Key"
   :resp-len-iv "AEAD Resp Header Len IV"
   :resp-key "AEAD Resp Header Key"
   :resp-iv "AEAD Resp Header IV"})

(def kdf-base
  "Vmess base kdf."
  (-> (crypto/->sha256-kdf)
      (crypto/->recur-kdf (b/of-str kdf-base-label))))

(def kdfs
  "Vmess kdfs."
  (->> kdf-labels
       (map
        (fn [[k l]]
          [k (crypto/->recur-kdf kdf-base (b/of-str l))]))
       (into {})))

(defn reduce-kdf
  "Add more labels to kdf."
  [kdf & labels]
  (->> labels (reduce crypto/->recur-kdf kdf)))

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
        auth-key (-> (crypto/kdf-digest! (:aid kdfs) cmd-key) (b/sub! 0 16))]
    {:uuid uuid :cmd-key cmd-key :auth-key auth-key}))

(comment
  (->id (random-uuid)))

(defn ->auth-param
  "Construct vmess auth param."
  []
  {:now (crypto/now-msec) :nonce (b/rand 4)})

(def st-aid
  "Struct of vmess auth id."
  (st/tuple
   st/int64-be
   (st/bytes-fixed 4)))

(defn ->eaid
  "Get vmess eaid."
  ([id]
   (->eaid id (->auth-param)))
  ([{:keys [auth-key]} {:keys [now nonce]}]
   (let [aid (st/pack [now nonce] st-aid)
         c (st/pack (crypto/crc32 aid) st/uint16-be)]
     (crypto/aes128-ecb-encrypt auth-key (b/concat! aid c)))))

;;; param

(defn ->param
  "Construct vmess connection param."
  [id addr]
  (let [key (b/rand 16) iv (b/rand 16)]
    {:id id
     :addr addr
     :stage :init
     :key key
     :iv iv
     :rkey (b/sub! (crypto/sha256 key) 0 16)
     :riv (b/sub! (crypto/sha256 iv) 0 16)
     :nonce (b/rand 8)
     :verify (rand-int 256)
     :pad (b/rand (rand-int 16))}))

(defn len-masks-seq
  "Generate seq of len masks."
  [b]
  (let [r (crypto/shake128-reader b)]
    (repeatedly #(r 2))))

(defn crypt-ivs-seq
  "Generate seq of crypt ivs."
  ([iv]
   (crypt-ivs-seq iv 0))
  ([iv cnt]
   (lazy-seq
    (cons
     (b/concat! (st/pack cnt st/uint16-be) iv)
     (crypt-ivs-seq iv (inc cnt))))))

(defn ->crypt-state
  "Construct base crypt state."
  [key iv param]
  {:key (crypto/->aes-key key)
   :crypt-ivs (crypt-ivs-seq (b/sub! iv 2 12))
   :len-masks (len-masks-seq iv)
   :param param})

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
   :host (-> (st/bytes-var :uint8) st/wrap-str)))

(defn ->req
  "Get vmess request."
  [{:keys [addr iv key verify pad]}]
  (-> {:ver 1
       :iv iv
       :key key
       :verify verify
       :opt 5 ; M|S
       :pad-sec [(b/count pad) 3] ; AESGCM
       :rsv 0
       :cmd 1 ; TCP
       :port (second addr)
       :host (first addr)}
      (st/pack st-req)
      (b/concat! pad)))

(defmethod advance-encrypt-state :wait-first-frame [state b]
  (let [{:keys [param]} state
        {:keys [id nonce]} param
        eaid (->eaid id)
        req (->req param)
        elen (crypto/aes128-gcm-encrypt
              (b/sub! (crypto/kdf-digest! (-> (:req-len-key kdfs) (reduce-kdf eaid nonce)) (:cmd-key id)) 0 16)
              (b/sub! (crypto/kdf-digest! (-> (:req-len-iv kdfs) (reduce-kdf eaid nonce)) (:cmd-key id)) 0 12)
              ;; decrypted req len
              (st/pack (b/count req) st/uint16-be)
              eaid)
        ereq (crypto/aes128-gcm-encrypt
              (b/sub! (crypto/kdf-digest! (-> (:req-key kdfs) (reduce-kdf eaid nonce)) (:cmd-key id)) 0 16)
              (b/sub! (crypto/kdf-digest! (-> (:req-iv kdfs) (reduce-kdf eaid nonce)) (:cmd-key id)) 0 12)
              req
              eaid)
        state (assoc state :stage :wait-frame)
        [eb state] (advance-encrypt-state state b)]
    [(b/concat! eaid nonce elen ereq eb) state]))

(defmethod advance-encrypt-state :wait-frame [state b]
  (let [{:keys [key crypt-ivs len-masks]} state
        eb (crypto/aes128-gcm-encrypt key (first crypt-ivs) b (b/empty))
        len (-> (b/count eb) (bit-xor (first len-masks)) (st/pack st/uint16-be))]
    [(b/concat! len eb)
     (-> state
         (update :crypt-ivs rest)
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
  (let [{:keys [buffer rkey riv]} state]
    (if (< (b/count buffer) 18)
      [nil state]
      (let [[elen buffer] (b/split-at! 18 buffer)
            ;; decrypted req len
            len (-> (crypto/aes128-gcm-decrypt
                     (b/sub! (crypto/kdf-digest! (:resp-len-key kdfs) rkey) 0 16)
                     (b/sub! (crypto/kdf-digest! (:resp-len-iv kdfs) riv) 0 12)
                     elen
                     (b/empty))
                    (st/unpack st/uint16-be))]
        ;; assoc encrypted req len
        [nil (assoc state :stage :wait-resp :buffer buffer :len (+ len 16))]))))

(def st-resp
  "Struct of vmess response."
  (st/keys
   :verify st/uint8
   :opt st/uint8
   :cmd st/uint8
   :data (st/bytes-var st/uint8)))

(defmethod advance-decrypt-state :wait-resp [state]
  (let [{:keys [buffer rkey riv verify len]} state]
    (if (< (b/count buffer) len)
      [nil state]
      (let [[eresp buffer] (b/split-at! len buffer)
            resp (-> (crypto/aes128-gcm-decrypt
                      (b/sub! (crypto/kdf-digest! (:resp-key kdfs) rkey) 0 16)
                      (b/sub! (crypto/kdf-digest! (:resp-iv kdfs) riv) 0 12)
                      eresp
                      (b/empty))
                     (st/unpack st-resp))]
        (assert (= verify (:verify resp)))
        [nil (assoc state :stage :wait-frame-len :buffer buffer)]))))

(defn decrypt-len
  "Decrypt len, assoc decrypted len in state."
  [state len]
  (let [{:keys [len-masks]} state]
    (-> state
        (assoc :len (-> len (st/unpack st/uint16-be) (bit-xor (first len-masks))))
        (update :len-masks rest))))

(defmethod advance-decrypt-state :wait-frame-len [state]
  (let [{:keys [buffer]} state]
    (if (< (b/count buffer) 2)
      [nil state]
      (let [[len buffer] (b/split-at! 2 buffer)]
        [nil (-> state
                 (assoc :stage :wait-frame :buffer buffer)
                 (decrypt-len len))]))))

(defmethod advance-decrypt-state :wait-frame [state]
  (let [{:keys [key crypt-ivs buffer len]} state]
    (if (< (b/count buffer) len)
      [nil state]
      (let [[eb buffer] (b/split-at! len buffer)
            iv (first crypt-ivs)
            b (crypto/aes128-gcm-decrypt key iv eb (b/empty))
            stage (if (b/empty? b) :closed :wait-frame-len)]
        [b (-> state
               (assoc :stage stage :buffer buffer)
               (update :crypt-ivs rest))]))))

(defmethod advance-decrypt-state :closed [state]
  (assert (b/empty? (:buffer state)))
  [nil state])

(defn advance-decrypt-state-recur
  "Recursive advance decrypt state."
  [state b]
  (let [state (update state :buffer b/concat! b)]
    (loop [bs [] state state]
      (let [[b state] (advance-decrypt-state state)]
        (if (nil? b)
          [(b/join! bs) state]
          (recur (conj bs b) state))))))

(defn ->decrypt-xform
  "Construct vmess decrypt trans function for async chan."
  [state]
  (let [vstate (volatile! state)]
    (fn [rf]
      (fn
        ([]
         (assert (= (:stage @vstate) :closed))
         (rf))
        ([result]
         (assert (= (:stage @vstate) :closed))
         (rf result))
        ([result input]
         (let [[b state] (advance-decrypt-state-recur state input)]
             (vreset! vstate state)
             (rf result b)))))))

;;; connect

(defn ->xform-pair
  "Construct vmess xform pair."
  [param]
  [(->decrypt-xform (->decrypt-state param))
   (->encrypt-xform (->encrypt-state param))])

(defmethod proto/->proxy-connect-info :vmess [{:keys [addr]} {:keys [id net-opts]}]
  (let [param (->param id addr)]
    {:net-opts net-opts :xform-pair (->xform-pair param)}))
