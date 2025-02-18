(ns vmessc.crypto
  (:require [clj-bytes.core :as b])
  (:import [java.util.zip CRC32]
           [java.security MessageDigest]
           [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec GCMParameterSpec]
           [org.bouncycastle.crypto.digests SHAKEDigest]))

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
  (let [r 0x811c9dc5
        p 0x01000193
        m 0xffffffff
        rf #(-> (bit-xor %1 %2) (* p) (bit-and m))]
    (->> (seq b) (reduce rf r))))

^:rct/test
(comment
  (crc32 (b/of-str "hello")) ; => 907060870
  (fnv1a (b/of-str "hello")) ; => 1335831723
  )

;;; digest

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

;;;; vmess digest

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
  (def r (shake128-reader (b/of-str "hello")))
  (b/hex (r 2)) ; => "8eb4"
  (b/hex (r 2)) ; => "b6a9"
  )

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
