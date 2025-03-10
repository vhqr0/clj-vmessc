(ns vmessc.core
  (:require [clojure.string :as str]
            [clojure.edn :as edn]
            [clj-proxy.core :as prx]
            clj-proxy.net
            clj-proxy.socks5
            [vmessc.vmess :as vmess])
  (:import [java.util Date]
           [java.text SimpleDateFormat]))

;;; utils

(def ^:dynamic *log-fn* prn)

(defn now
  "Get current date inst."
  []
  (Date.))

(def ^:dynamic *date-formatter*
  "Inst formatter."
  (SimpleDateFormat. "yyyy-MM-dd-HH:mm:ss"))

(defn inst-fmt
  "Format inst."
  ([]
   (inst-fmt (now)))
  ([i]
   (-> *date-formatter* (.format i))))

(defn with-conf-prefix
  [name]
  (str "conf/" name))

(defn with-bak-prefix
  [name]
  (with-conf-prefix (str "bak/" (inst-fmt) \. name)))

(comment
  (inst-fmt)
  (with-bak-prefix "tags.edn"))

(defn conf-spit
  [name data]
  (spit (with-bak-prefix name) data)
  (spit (with-conf-prefix name) data))

(defn conf-slurp
  [name]
  (slurp (with-conf-prefix name)))

;;; tags

(defn tags-gen
  ([]
   (tags-gen ["tags-dlc.edn" "tags-custom.edn"]))
  ([sources]
   (->> sources
        (mapcat #(edn/read-string (conf-slurp %)))
        vec
        (conf-spit "tags.edn"))))

(defn tags-load
  []
  (edn/read-string (conf-slurp "tags.edn")))

;;;; dlc

;; domain list community
;; origin: https://github.com/v2fly/domain-list-community
;; my fork: https://github.com/vhqr0/domain-list-community

(defn dlc-data-path
  [name]
  (str "domain-list-community/data/" name))

(defn dlc-data-slurp
  [name]
  (conf-slurp (dlc-data-path name)))

(comment
  (dlc-data-path "cn") ; => "domain-list-community/data/cn"
  )

(def dlc-line-re
  #"^((\w+):)?([^\s\t#]+)( @([^\s\t#]+))?")

(comment
  (re-matches dlc-line-re "a.baidu.com") ; => ["a.baidu.com" nil nil "a.baidu.com" nil nil]
  (re-matches dlc-line-re "a.baidu.com @ads") ; => ["a.baidu.com @ads" nil nil "a.baidu.com" " @ads" "ads"]
  (re-matches dlc-line-re "include:geolocation-cn") ; => ["include:geolocation-cn" "include:" "include" "geolocation-cn" nil nil]
  )

(def dlc-tag-map
  {"ads" :block "cn" :direct "!cn" :proxy})

(defn dlc-tags-seq
  "Return seq of tags."
  [name default-tag]
  (->> (dlc-data-slurp name)
       str/split-lines
       (mapcat
        (fn [line]
          (let [line (-> (first (str/split line #"#" 2)) str/trim)]
            (when-not (str/blank? line)
              (if-let [matches (re-matches dlc-line-re line)]
                (case (or (get matches 2) "domain")
                  ("domain" "full") (let [domain (get matches 3)
                                          tag (get matches 5)
                                          tag (get dlc-tag-map tag default-tag)]
                                      [[domain tag]])
                  "include" (let [name (get matches 3)]
                              (dlc-tags-seq name default-tag))
                  ;; we don't support regexp yet
                  "regexp" nil
                  (*log-fn* {:type :dlc/parse-error :line line}))
                (*log-fn* {:type :dlc/parse-error :line line}))))))))

(defn dlc-tags-gen
  []
  (->> (concat
        (dlc-tags-seq "cn" :direct)
        (dlc-tags-seq "geolocation-!cn" :proxy))
       vec
       (conf-spit "tags-dlc.edn")))

;;; sub

(defn sub->edn
  [s]
  (->> (vmess/v2rayn-sub->urls s)
       (filter #(str/starts-with? % "vmess://"))
       (mapv
        (fn [url]
          (try
            (-> url vmess/vmess-url->json vmess/vmess-json->edn)
            (catch Exception e
              (*log-fn* {:type :sub/parse-error :url url :ex e})))))))

(defn sub-fetch
  []
  (->> (conf-slurp "sub.url") str/trim slurp (conf-spit "sub.txt")))

(defn sub-gen
  []
  (->> (conf-slurp "sub.txt") sub->edn vec (conf-spit "sub.edn")))

(defn sub-load
  []
  (edn/read-string (conf-slurp "sub.edn")))

;;; server

(defn port-load
  []
  (edn/read-string (conf-slurp "port.edn")))

(defn server-context-load
  ([]
   (let [port (port-load)
         tag-map (->> (tags-load) (into {}))
         sub-opts (->> (sub-load) (filter :enable?) (mapv vmess/vmess-edn->opts))]
     (assert (seq sub-opts))
     (server-context-load port tag-map sub-opts)))
  ([port tag-map sub-opts]
   {:log-fn *log-fn*
    :net-server-opts {:type :tcp :port port}
    :proxy-server-opts {:type :socks5}
    :connect-opts {:type :tag-dispatch
                   :name "main"
                   :tag-map tag-map
                   :default-tag :direct
                   :sub-opts {:direct {:type :direct :name "direct"}
                              :block {:type :block :name "block"}
                              :proxy {:type :rand-dispatch :name "proxy" :sub-opts sub-opts}}}}))

(defn start-server
  ([]
   (prx/start-server (server-context-load)))
  ([context]
   (prx/start-server context)))
