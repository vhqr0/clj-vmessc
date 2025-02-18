(ns vmessc.cli
  (:require [clojure.string :as str]
            [vmessc.crypto :as crypto]
            vmessc.socks5
            vmessc.vmess))

(defn sub-paths
  "Get sub file paths."
  [now]
  [(str "conf/bak/sub.txt." now) "conf/sub.txt"])

(defn fetch-sub
  "Fetch sub."
  ([]
   (fetch-sub (-> (crypto/now) inst-ms)))
  ([now]
   (let [s (-> "conf/sub.url" slurp str/trim slurp)]
     (doseq [path (sub-paths now)]
       (spit path s)))))
