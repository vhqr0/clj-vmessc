(ns vmessc.cli.v2rayn
  (:require [clojure.string :as str]
            [vmessc.cli.core :as core]))

(def ^:dynamic *url-path*
  "V2RayN subscribe URL path."
  "conf/v2rayn-sub.url")

(def ^:dynamic *sub-path*
  "V2RayN subscribe edn path."
  "conf/v2rayn-sub.edn")

(def ^:dynamic *bak-name*
  "Backup name of V2RayN subscribe edn file."
  "v2rayn-sub.edn")

(defn sub-paths
  "Get sub file paths."
  []
  [(str (core/bak-prefix) *bak-name*) *sub-path*])

(defn fetch
  "Fetch sub."
  []
  (let [s (-> *url-path* slurp str/trim slurp)]
    (doseq [path (sub-paths)]
      (spit path s))))
