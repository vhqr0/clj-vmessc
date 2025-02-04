(ns vmessc.crypto
  (:require [clj-bytes.core :as b])
  (:import [java.util Date]
           [java.time Instant]
           [java.util.zip CRC32]
           [java.security MessageDigest]
           [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec GCMParameterSpec]
           [org.bouncycastle.crypto.digests SHAKEDigest]))

;;; time

(defn now-sec
  "Get current unix time stamp in sec."
  []
  (.getTime (Date.)))

(defn now-msec
  "Get current unix time stamp in msec."
  []
  (let [sec (now-sec)]
    (int (/ sec 1000))))

(defn sec->inst
  "Convert unix time stamp in sec to inst."
  [sec]
  (Date/from (Instant/ofEpochSecond sec)))

(defn msec->inst
  "Convert unix time stamp in msec to inst."
  [msec]
  (Date/from (Instant/ofEpochMilli msec)))

;;; check sum

(defn crc32
  "Get crc32 check sum in int."
  [b]
  (let [c (doto (CRC32.)
            (.update b))]
    (.getValue c)))

(defn fnv1a
  "Get fnv1a check sum in int."
  [b]
  (let [p 0x01000193
        m 0xffffffff]
    (->> (range (alength b))
         (reduce
          (fn [r i]
            (bit-and m (* p (bit-xor r (aget b i)))))
          0x811c9dc5))))

;;; digest

(defn digest
  "Message digest."
  [b algo]
  (-> (MessageDigest/getInstance algo)
      (.digest b)))

(defn md5 [b] (digest b "MD5"))
(defn sha256 [b] (digest b "SHA-256"))

(defprotocol KDF
  "Abstraction for clonable vmess kdf function."
  (kdf-clone [this]
    "Clone kdf object.")
  (kdf-update! [this b]
    "Update kdf state, impure.")
  (kdf-digest! [this b]
    "Digest, impure."))

(defrecord SHA256KDF [d]
  KDF
  (kdf-clone [_]
    (->SHA256KDF (.clone d)))
  (kdf-update! [_ b]
    (.update d b))
  (kdf-digest! [_ b]
    (.digest d b)))

(defrecord RecurKDF [inner outer]
  KDF
  (kdf-clone [_]
    (->RecurKDF (kdf-clone inner) (kdf-clone outer)))
  (kdf-update! [_ b]
    (kdf-update! inner b))
  (kdf-digest! [_ b]
    (kdf-digest! outer (kdf-digest! inner b))))

(defn ->sha256-kdf
  "Construct sha256 kdf."
  []
  (->SHA256KDF (MessageDigest/getInstance "SHA-256")))

(defn hmac-expand-key
  "Expand hmac key."
  [^bytes k]
  (assert (<= (b/count k) 64))
  (let [^bytes ik (-> (byte-array 64) (b/fill! 0x36))
        ^bytes ok (-> (byte-array 64) (b/fill! 0x5c))]
    (dotimes [i (alength k)]
      (let [b (aget k i)]
        (aset-byte ik i (unchecked-byte (bit-xor b 0x36)))
        (aset-byte ok i (unchecked-byte (bit-xor b 0x5c)))))
    [ik ok]))

(defn ->recur-kdf
  "Construct recur kdf, based on a base kdf and label."
  [kdf ^bytes label]
  (let [[ik ok] (hmac-expand-key label)
        id (doto (kdf-clone kdf)
             (kdf-update! ik))
        od (doto (kdf-clone kdf)
             (kdf-update! ok))]
    (->RecurKDF id od)))

;;; mask generator

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
  (def r (shake128-reader (b/of-str "hello"))))

;;; cipher

(defn ->aes-key
  "Get expanded AES key."
  [key]
  (SecretKeySpec. key "AES"))

(defn aes128-ecb-crypt
  "Encrypt or decrypt bytes with AES128 ECB."
  [key b mode]
  (let [key (if-not (bytes? key) key (->aes-key key))
        c (doto (Cipher/getInstance "AES/ECB/PKCS5Padding")
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
