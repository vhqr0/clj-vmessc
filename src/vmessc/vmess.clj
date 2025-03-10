(ns vmessc.vmess
  (:require [clojure.string :as str]
            [clojure.data.json :as json]
            [clojure.core.async :as a]
            [clj-bytes.core :as b]
            [clj-bytes.struct :as st]
            [clj-proxy.core :as prx])
  (:import [java.util Date]
           [java.util.zip CRC32]
           [java.security MessageDigest]
           [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec GCMParameterSpec]
           [org.bouncycastle.crypto.digests SHAKEDigest]
           [javax.net.ssl SSLParameters SSLContext SSLEngine SNIHostName]
           [io.netty.handler.ssl SslHandler]))

;; vmess legacy: https://github.com/v2fly/v2fly-github-io/blob/master/docs/developer/protocols/vmess.md
;; vmess aead: https://github.com/v2fly/v2fly-github-io/issues/20/
;; v2rayn sub: https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link

;;; crypto

;;;; now

(defn now
  "Get current inst."
  []
  (Date.))

;;;; check sum

(defn crc32
  "Get crc32 check sum in int."
  [b]
  (let [c (doto (CRC32.)
            (.update b))]
    (.getValue c)))

(defn fnv1a
  "Get fnv1a check sum in int."
  [b]
  (let [r 0x811c9dc5
        p 0x01000193
        m 0xffffffff
        rf #(-> (bit-xor %1 %2) (* p) (bit-and m))]
    (->> (b/useq b) (reduce rf r))))

^:rct/test
(comment
  (crc32 (b/of-str "hello")) ; => 907060870
  (fnv1a (b/of-str "hello")) ; => 1335831723
  )

;;;; digest

(defn digest
  "Message digest."
  [b algo]
  (-> (MessageDigest/getInstance algo)
      (.digest b)))

(defn md5 [b] (digest b "MD5"))
(defn sha256 [b] (digest b "SHA-256"))

^:rct/test
(comment
  (-> (b/of-str "hello") md5 b/hex)
  ;; => "5d41402abc4b2a76b9719d911017c592"
  (-> (b/of-str "hello") sha256 b/hex)
  ;; => "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
  )

;;;;; vmess digest

(defprotocol VmessDigest
  "Abstraction for clonable vmess digest function."
  (vd-clone [this]
    "Clone vmess digest state.")
  (vd-update! [this b]
    "Update digest state, impure.")
  (vd-digest! [this b]
    "Do digest, impure."))

(defrecord SHA256VmessDigest [d]
  VmessDigest
  (vd-clone [_]
    (->SHA256VmessDigest (.clone d)))
  (vd-update! [_ b]
    (.update d b))
  (vd-digest! [_ b]
    (.digest d b)))

(defrecord RecurVmessDigest [ivd ovd]
  VmessDigest
  (vd-clone [_]
    (->RecurVmessDigest (vd-clone ivd) (vd-clone ovd)))
  (vd-update! [_ b]
    (vd-update! ivd b))
  (vd-digest! [_ b]
    (vd-digest! ovd (vd-digest! ivd b))))

(defn ->sha256-vd
  "Construct SHA256 vmess digest state."
  []
  (->SHA256VmessDigest (MessageDigest/getInstance "SHA-256")))

(defn hmac-expand-key
  "Expand key in HMAC format."
  [^bytes k]
  (if (> (b/count k) 64)
    (throw (ex-info "vmess digest assert key length <= 64" {}))
    (let [^bytes ik (-> (byte-array 64) (b/fill! 0x36))
          ^bytes ok (-> (byte-array 64) (b/fill! 0x5c))]
      (dotimes [i (alength k)]
        (let [b (aget k i)]
          (aset-byte ik i (unchecked-byte (bit-xor b 0x36)))
          (aset-byte ok i (unchecked-byte (bit-xor b 0x5c)))))
      [ik ok])))

(defn ->recur-vd
  "Construct recur vmess digest state,
  based on a base digest state and key."
  [vd ^bytes k]
  (let [[ik ok] (hmac-expand-key k)
        ivd (doto (vd-clone vd) (vd-update! ik))
        ovd (doto (vd-clone vd) (vd-update! ok))]
    (->RecurVmessDigest ivd ovd)))

^:rct/test
(comment
  (-> (->sha256-vd)
      (->recur-vd (b/of-str "hello"))
      (vd-digest! (b/of-str "world"))
      b/hex)
  ;; => "f1ac9702eb5faf23ca291a4dc46deddeee2a78ccdaf0a412bed7714cfffb1cc4"
  )

;;;; mask generator

(defn shake128-reader
  "Get reader function of shake128 random bytes generator."
  [b]
  (let [d (doto (SHAKEDigest. 128)
            (.update b 0 (alength b)))]
    (fn [n]
      (let [b (byte-array n)]
        (.doOutput d b 0 n)
        b))))

(comment
  (def r (shake128-reader (b/of-str "hello")))
  (b/hex (r 2)) ; => "8eb4"
  (b/hex (r 2)) ; => "b6a9"
  )

;;;; cipher

(defn ->aes-key
  "Get expanded AES key."
  [key]
  (SecretKeySpec. key "AES"))

(defn aes128-ecb-crypt
  "Encrypt or decrypt bytes with AES128 ECB."
  [key b mode]
  (let [key (if-not (bytes? key) key (->aes-key key))
        c (doto (Cipher/getInstance "AES/ECB/NoPadding")
            (.init mode key))]
    (.doFinal c b)))

(defn aes128-ecb-encrypt [key b] (aes128-ecb-crypt key b Cipher/ENCRYPT_MODE))
(defn aes128-ecb-decrypt [key b] (aes128-ecb-crypt key b Cipher/DECRYPT_MODE))

(defn aes128-gcm-crypt
  "Encryt or decrypt bytes with AES128 GCM."
  [key iv b aad mode]
  (let [key (if-not (bytes? key) key (->aes-key key))
        iv (GCMParameterSpec. 128 iv)
        c (doto (Cipher/getInstance "AES/GCM/NoPadding")
            (.init mode key iv)
            (.updateAAD aad))]
    (.doFinal c b)))

(defn aes128-gcm-encrypt [key iv b aad] (aes128-gcm-crypt key iv b aad Cipher/ENCRYPT_MODE))
(defn aes128-gcm-decrypt [key iv b aad] (aes128-gcm-crypt key iv b aad Cipher/DECRYPT_MODE))

;;; vmess

;;;; kdf

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
  (-> (->sha256-vd)
      (->recur-vd (b/of-str kdf-1-label))))

(def kdf-2-vds
  "Vmess kdf second level digest states."
  (->> kdf-2-labels
       (map
        (fn [[k l]]
          (let [vd (-> kdf-1-vd (->recur-vd (b/of-str l)))]
            [k vd])))
       (into {})))

(defn kdf
  "Vmess kdf digest."
  [type b & labels]
  {:pre [(contains? kdf-2-vds type)]}
  (let [vd (->> labels
                (reduce
                 (fn [vd ^bytes label]
                   (-> vd (->recur-vd label)))
                 (vd-clone (get kdf-2-vds type))))]
    (vd-digest! vd b)))

;;;; auth

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
  (let [cmd-key (md5 (b/concat! (uuid->bytes uuid) (b/of-str vmess-uuid)))
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
  {:now (now) :nonce (b/rand 4)})

(defn ->aid
  "Convert auth param to aid bytes."
  [{:keys [now nonce]}]
  (let [now-sec (int (/ (inst-ms now) 1000.0))
        aid (-> [now-sec nonce] (st/pack st-aid))
        crc32 (-> (crc32 aid) (st/pack st/uint32-be))]
    (b/concat! aid crc32)))

(defn ->eaid
  "Construct vmess eaid."
  ([id]
   (->eaid id (->auth-param)))
  ([{:keys [auth-key]} param]
   (let [aid (->aid param)]
     (aes128-ecb-encrypt auth-key aid))))

(comment
  (-> (random-uuid) ->id ->eaid))

;;;; param

(defn ->param
  "Construct vmess connection param."
  [id addr]
  (let [key (b/rand 16) iv (b/rand 16)]
    {:id id
     :addr addr
     :key key
     :iv iv
     :rkey (-> (sha256 key) (b/sub! 0 16))
     :riv (-> (sha256 iv) (b/sub! 0 16))
     :nonce (b/rand 8)
     :verify (rand-int 256)
     :pad (b/rand (rand-int 16))}))

(comment
  (-> (->id (random-uuid)) (->param ["www.google.com" 80])))

(defn len-masks-seq
  "Generate seq of len masks."
  [b]
  (let [r (shake128-reader b)]
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
  {:key (->aes-key key)
   :ivs (ivs-seq (b/sub! iv 2 12))
   :len-masks (len-masks-seq iv)
   :param param})

(comment
  (->> (len-masks-seq (b/rand 16)) (take 10))
  (->> (ivs-seq (b/rand 12)) (take 10) (map b/hex)))

;;;; encrypt

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
        fnv1a (-> (fnv1a req) (st/pack st/uint32-be))]
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
               (aes128-gcm-encrypt key iv len eaid))
        ereq (let [key (-> (kdf :req-key cmd-key eaid nonce) (b/sub! 0 16))
                   iv (-> (kdf :req-iv cmd-key eaid nonce) (b/sub! 0 12))]
               (aes128-gcm-encrypt key iv req eaid))
        [eb state] (-> state
                       (assoc :stage :wait-frame)
                       (advance-encrypt-state b))]
    [(b/concat! eaid elen nonce ereq eb) state]))

(defmethod advance-encrypt-state :wait-frame [state b]
  (let [{:keys [key ivs len-masks]} state
        eb (aes128-gcm-encrypt key (first ivs) b (b/empty))
        elen (-> (b/count eb) (bit-xor (first len-masks)) (st/pack st/uint16-be))]
    [(b/concat! elen eb)
     (-> state
         (update :ivs rest)
         (update :len-masks rest))]))

(defn ->encrypt-xf
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

;;;; decrypt

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
            len (-> (aes128-gcm-decrypt key iv elen (b/empty))
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
            resp (-> (aes128-gcm-decrypt key iv eresp (b/empty))
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
            b (aes128-gcm-decrypt key (first ivs) eb (b/empty))
            stage (if (b/empty? b) :closed :wait-frame-len)
            [nb state] (-> state
                           (assoc :stage stage :buffer buffer)
                           (update :ivs rest)
                           advance-decrypt-state)
            b (cond-> b
                (some? nb) (b/concat! nb))]
        [b state]))))

(defmethod advance-decrypt-state :closed [state]
  (if-not (b/empty? (:buffer state))
    (throw (ex-info "invalid data after vmess connection closed" {}))
    [nil state]))

(defn ->decrypt-xf
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

;;;; register

(defn ->xf-pair
  "Construct vmess xf pair."
  [param]
  [(->decrypt-xf (->decrypt-state param))
   (->encrypt-xf (->encrypt-state param))])

(defn ->server
  [server param]
  (let [[ixf oxf] (->xf-pair param)
        ich (a/chan 1024 ixf)
        och (a/chan 1024 oxf)]
    (a/pipe (first server) ich)
    (a/pipe och (second server))
    [ich och]))

(defrecord VmessClient [param]
  prx/HandShake
  (hs-update [_ _b] (throw (ex-info "invalid update in client handshake" {})))
  (hs-advance [this] [nil this])
  (hs-info [_] {:type :ok :server-xf #(->server % param)}))

(defmethod prx/->proxy-client :vmess [addr {:keys [id]}]
  (->VmessClient (->param id addr)))


;;; v2rayn

(defn v2rayn-sub->urls
  "Convert subscribe content to URLs."
  [s]
  (-> s b/of-base64 b/str (str/split #"\r\n")))

(defn vmess-url->json
  "Convert vmess URL to json data."
  [s]
  {:pre [(str/starts-with? s "vmess://")]}
  (-> (subs s 8) b/of-base64 b/str json/read-str))

(defn vmess-json->edn
  "Convert vmess json data to edn."
  [{:strs [v ps add port id _aid scy net type host path tls sni alpn _fp]
    :or {scy "auto" net "tcp" type "none"}}]
  {:pre [(= v "2") (= scy "auto") (= type "none")]}
  (let [net (case net "tcp" :tcp "ws" :ws)
        ws? (= net :ws)
        tls? (= tls "tls")
        port (Integer/parseInt port)]
    (cond-> {:name ps :uuid id :net net :addr [add port] :tls? tls?}
      ws?  (merge (cond-> {}
                    (some? path) (assoc :http-path path)
                    (some? host) (assoc :http-host host)))
      tls? (merge (cond-> {}
                    (some? sni) (assoc :tls-sni sni)
                    (some? alpn) (assoc :tls-alpn (str/split alpn #",")))))))

(defn ->tls-param
  "Construct TLS param, support sni and alpn."
  [{:keys [sni alpn]}]
  (let [param (SSLParameters.)]
    (when (some? sni)
      (let [sni (if (string? sni) [sni] sni)
            sni-array (->> sni (map #(SNIHostName. %)) (into-array SNIHostName))]
        (.setServerNames param (java.util.Arrays/asList sni-array))))
    (when (some? alpn)
      (let [alpn (if (string? alpn) [alpn] alpn)
            alpn-array (->> alpn (into-array String))]
        (.setApplicationProtocols param alpn-array)))
    param))

(defn ->tls-context
  "Construct netty TLS context, support sni and alpn."
  [opts]
  (let [^SSLParameters param (->tls-param opts)
        ^SSLContext context (SSLContext/getDefault)
        ^SSLEngine engine (doto (.createSSLEngine context)
                            (.setSSLParameters param))]
    (SslHandler. engine)))

(defn vmess-edn->net-opts
  [{:keys [net addr tls? http-path http-host tls-sni tls-alpn]}]
  (let [tls-context (when tls?
                      (let [opts (cond-> {}
                                   (some? tls-sni) (assoc :sni tls-sni)
                                   (some? tls-alpn) (assoc :alpn tls-alpn))]
                        (when (seq opts)
                          (->tls-context opts))))]
    (cond-> {:type net :addr addr :tls? tls?}
      (= net :ws) (merge (cond-> {}
                           (some? http-path) (assoc :http-path http-path)
                           (some? http-host) (assoc :http-host http-host)))
      (some? tls-context) (assoc :tls-context tls-context))))

(defn vmess-edn->proxy-opts
  [{:keys [uuid]}]
  {:type :vmess :id (->id uuid)})

(defn vmess-edn->opts
  [{:keys [name] :as edn}]
  {:type :proxy
   :name name
   :net-opts (vmess-edn->net-opts edn)
   :proxy-opts (vmess-edn->proxy-opts edn)})
