(ns vmessc.cli.vn
  (:require [clojure.edn :as edn]
            [clojure.string :as str]
            [clojure.data.json :as json]
            [clj-bytes.core :as b]
            [vmessc.cli.core :as core]))

;;; v2rayn

;; V2RayN vmess subscribe format:
;; https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link

(defn sub-content->urls
  "Convert subscribe content to URLs."
  [s]
  (-> s b/of-base64 b/str (str/split #"\r\n")))

(defn vmess-url->json
  "Convert vmess URL to json data."
  [s]
  {:pre [(str/starts-with? s "vmess://")]}
  (-> (subs s 8) b/of-base64 b/str json/read-str))

(defn vmess-json->param
  "Convert vmess json data to param."
  [{:strs [v ps add port id _aid scy net type host path tls sni alpn _fp]
    :or {scy "auto" net "tcp" type "none"}}]
  {:pre [(= v "2") (= scy "auto") (= type "none")]}
  (let [net-opts (merge
                  {:host add :port (edn/read-string port)}
                  (case net
                    "tcp" {:type :tcp}
                    "ws"  (cond-> {:type :ws}
                            (some? path) (assoc :http-path path)
                            (some? host) (assoc :http-host host)))
                  (when (= tls "tls")
                    {:tls? true
                     :tls-opts (cond-> {}
                                 (some? sni) (assoc :sni sni)
                                 (some? alpn) (assoc :alpn (str/split alpn #",")))}))]
    {:name ps :uuid id :net net-opts}))

(defn sub-content->vmess-params
  "Convert subscribe content to vmess params."
  [s]
  (->> (sub-content->urls s)
       (filter #(str/starts-with? % "vmess://"))
       (map
        (fn [url]
          (let [json (vmess-url->json url)]
            (try
              (vmess-json->param json)
              (catch Exception e
                (core/log {:level :error :type :cli/parse-error :app :vn :content-type :vn/json :content json :exc e}))))))))

;;; cli

(def ^:dynamic *url-path*
  "V2RayN subscribe URL path."
  "conf/vn-sub.url")

(def ^:dynamic *sub-path*
  "V2RayN subscribe edn path."
  "conf/vn-sub.txt")

(def ^:dynamic *bak-name*
  "Backup name of V2RayN subscribe edn file."
  "vn-sub.txt")

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

(defn parse
  "Parse sub."
  []
  (let [s (-> *sub-path* slurp sub-content->vmess-params vec)]
    (spit core/*sub-path* s)))
