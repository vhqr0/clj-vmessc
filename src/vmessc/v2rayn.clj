(ns vmessc.v2rayn
  (:require [clojure.string :as str]
            [clojure.data.json :as json]
            [clj-bytes.core :as b]
            [vmessc.vmess :as vmess])
  (:import [javax.net.ssl SSLParameters SSLContext SSLEngine SNIHostName]
           [io.netty.handler.ssl SslHandler]))

;; https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link

;; term:
;; - sub-content: v2rayn sub url's http response content, that contain many urls
;; - vmess-json: json format v2rayn vmess config, that parse from sub-content url
;; - vmess-param: edn format v2rayn vmess config, that convert from vmess-json and store in a edn file
;; - vmess-opts: vmess proxy connect opts for clj-proxy, that convert from vmess-param

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
  (let [net (case net "tcp" :tcp "ws" :ws)
        ws? (= net :ws)
        tls? (= tls "tls")
        port (Integer/parseInt port)]
    (cond-> {:name ps :uuid id :net net :addr [add port] :tls? tls?}
      ws?  (merge (cond-> {}
                    (some? path) (assoc :http-path path)
                    (some? host) (assoc :http-host host)))
      tls? (merge (cond-> {}
                    (some? sni) (assoc :tls-sni sni)
                    (some? alpn) (assoc :tls-alpn (str/split alpn #",")))))))

(defn ->tls-param
  "Construct TLS param, support sni and alpn."
  [{:keys [sni alpn]}]
  (let [param (SSLParameters.)]
    (when (some? sni)
      (let [sni (if (string? sni) [sni] sni)
            sni-array (->> sni (map #(SNIHostName. %)) (into-array SNIHostName))]
        (.setServerNames param (java.util.Arrays/asList sni-array))))
    (when (some? alpn)
      (let [alpn (if (string? alpn) [alpn] alpn)
            alpn-array (->> alpn (into-array String))]
        (.setApplicationProtocols param alpn-array)))
    param))

(defn ->tls-context
  "Construct netty TLS context, support sni and alpn."
  [opts]
  (let [^SSLParameters param (->tls-param opts)
        ^SSLContext context (SSLContext/getDefault)
        ^SSLEngine engine (doto (.createSSLEngine context)
                            (.setSSLParameters param))]
    (SslHandler. engine)))

(defn vmess-param->net-opts
  [{:keys [net addr tls? http-path http-host tls-sni tls-alpn]}]
  (let [tls-context (when tls?
                      (let [opts (cond-> {}
                                   (some? tls-sni) (assoc :sni tls-sni)
                                   (some? tls-alpn) (assoc :alpn tls-alpn))]
                        (when (seq opts)
                          (->tls-context opts))))]
    (cond-> {:type net :addr addr :tls? tls?}
      (= net :ws) (merge (cond-> {}
                           (some? http-path) (assoc :http-path http-path)
                           (some? http-host) (assoc :http-host http-host)))
      (some? tls-context) (assoc :tls-context tls-context))))

(defn vmess-param->proxy-opts
  [{:keys [uuid]}]
  {:id (vmess/->id uuid)})

(defn vmess-param->opts
  [{:keys [name] :as param}]
  {:type :proxy
   :name name
   :net-opts (vmess-param->net-opts param)
   :proxy-opts (vmess-param->proxy-opts param)})
