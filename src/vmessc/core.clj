(ns vmessc.core
  (:require [clojure.string :as str]
            [clojure.edn :as edn]
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

(defn bak-prefix
  [name]
  (str "conf/bak/" (inst-fmt) \. name))

(comment
  (inst-fmt)
  (bak-prefix "tags.edn"))

;;; domain list community

;; origin: https://github.com/v2fly/domain-list-community
;; my fork: https://github.com/vhqr0/domain-list-community

(defn dlc-data-path [name]
  (str "conf/domain-list-community/data/" name))

(comment
  (dlc-data-path "cn") ; => "conf/domain-list-community/data/cn"
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
  (->> (slurp (dlc-data-path name))
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
  (let [tags (vec (concat
                   (dlc-tags-seq "cn" :direct)
                   (dlc-tags-seq "geolocation-!cn" :proxy)))]
    (spit "conf/tags-dlc.edn" tags)
    (spit (bak-prefix "tags-dlc.edn") tags)))

(defn tags-load
  []
  (->> (concat
        (edn/read-string (slurp "conf/tags-dlc.edn"))
        (edn/read-string (slurp "conf/tags-custom.edn")))
       (into {})))

;;; v2rayn sub

(defn sub->vmess-edn
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
  (let [s (-> "conf/sub.url" slurp str/trim slurp)]
    (spit "conf/sub.txt" s)
    (spit (bak-prefix "sub.txt") s)))

(defn sub-gen
  []
  (let [s (-> "conf/sub.txt" slurp sub->vmess-edn vec)]
    (spit "conf/sub.edn" s)
    (spit (bak-prefix "sub.edn") s)))

(defn sub-load
  []
  (-> "conf/sub.edn" slurp edn/read-string))

;;; server

(defn server-context
  [tag-map sub {:keys [port] :or {port 1080}}]
  {:log-fn prn
   :net-server-opts {:type :tcp :port port}
   :proxy-server-opts {:type :socks5}
   :connect-opts {:type :tag-dispatch
                  :name "main"
                  :tag-map tag-map
                  :default-tag :direct
                  :sub-opts {:direct {:type :direct :name "direct"}
                             :block {:type :block :name "block"}
                             :proxy {:type :rand-dispatch
                                     :name "proxy"
                                     :sub-opts (->> sub
                                                    (filter :enable?)
                                                    (mapv vmess/vmess-edn->opts))}}}})
