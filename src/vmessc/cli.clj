(ns vmessc.cli
  (:require [clojure.string :as str]
            [clojure.core.async :as a]
            [clojure.java.io :as io]
            [clj-commons.byte-streams :as bs]
            [vmessc.crypto :as crypto]
            [vmessc.net :as net]
            vmessc.socks5
            vmessc.vmess))

(defn fetch
  ([]
   (fetch (crypto/now-msec)))
  ([now]
   (let [url (-> "conf/subs.url" slurp str/trim)]
     (when-let [resp (a/<!! (net/request url))]
       (bs/transfer resp (io/file (str "conf/bak/subs.txt." now)))
       (bs/transfer resp (io/file "conf/subs.txt"))))))
