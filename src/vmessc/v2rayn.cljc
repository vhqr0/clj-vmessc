(ns vmessc.v2rayn
  (:require [clojure.edn :as edn]
            [clojure.string :as str]
            [clojure.data.json :as json]
            [clj-bytes.core :as b]))

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
       (map (comp vmess-url->json vmess-json->param))))
