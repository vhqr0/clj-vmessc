(ns vmessc.cli
  (:require [clojure.string :as str]
            [vmessc.crypto :as crypto]
            vmessc.socks5
            vmessc.vmess))

(defn fetch-subs
  ([]
   (fetch-subs (-> (crypto/now) inst-ms)))
  ([now]
   (let [subs (-> "conf/subs.url" slurp str/trim slurp)]
     (-> subs (spit (str "conf/bak/subs.txt." now)))
     (-> subs (spit "conf/bak/subs.txt")))))
