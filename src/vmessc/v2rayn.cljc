(ns vmessc.v2rayn
  (:require [clojure.edn :as edn]
            [clojure.string :as str]
            [clojure.data.json :as json]
            [clj-bytes.core :as b]))

(defn sub-content->urls
  [s]
  (-> s b/of-base64 b/str (str/split #"\r\n")))

(defn vmess-url->json
  [s]
  (assert (str/starts-with? s "vmess://"))
  (-> (subs s 8) b/of-base64 b/str json/read-str))

(defn vmess-json->param
  [d]
  (let [{:strs [v ps add port id scy net type host path tls sni alpn]} d]
    (assert (= v "2"))
    (when (some? scy)
      (assert (= scy "none")))
    (when (some? type)
      (assert (= type "none")))
    (let [net-opts {:type (case net "tcp" :tcp "ws" :ws)
                    :host add
                    :port (edn/read-string port)
                    :tls? (= tls "tls")}
          net-opts (if-not (= (:type net-opts) :ws)
                     net-opts
                     (cond-> net-opts
                       (some? path) (assoc :http-path path)
                       (some? host) (assoc :http-host host)))
          net-opts (if-not (:tls? net-opts)
                     net-opts
                     (let [tls-opts (cond-> {}
                                      (some? sni) (assoc :sni sni)
                                      (some? alpn) (assoc :alpn (str/split alpn #",")))]
                       (assoc net-opts :tls-opts tls-opts)))]
      {:name ps :uuid id :net net-opts})))

(defn sub-content->vmess-params
  [s]
  (->> (sub-content->urls s)
       (filter #(str/starts-with? % "vmess://"))
       (map (comp vmess-url->json vmess-json->param))))
