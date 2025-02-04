(ns vmessc.net
  (:require [clojure.core.async :as a]
            [manifold.deferred :as d]
            [manifold.stream :as s]
            [clj-commons.byte-streams :as bs]
            [aleph.tcp :as tcp]
            [aleph.http :as http]
            [aleph.http.websocket.client :as ws])
  (:import [java.net URI]
           [javax.net.ssl SSLContext SSLParameters SNIHostName]
           [io.netty.handler.ssl SslHandler]))

(defn deferred->ch
  ([deferred]
   (deferred->ch deferred identity))
  ([deferred xform]
   (let [ch (a/chan)]
     (-> deferred
         (d/on-realized
          (fn [data] (a/>!! ch (xform data)))
          (fn [_error] (a/close! ch))))
     ch)))

(defn connect-ch-pair
  [[ich och] stream]
  (s/connect stream ich)
  (s/connect och stream)
  [ich och])

;;; connect

(defn ->tls-context
  [{:keys [sni alpn]}]
  (let [param (SSLParameters.)]
    (when (some? sni)
      (.setServerNames param (java.util.List/of (SNIHostName. sni))))
    (when (some? alpn)
      (.setApplicationProtocols param (into-array String alpn)))
    (let [context (SSLContext/getDefault)
          engine (doto (.createSSLEngine context)
                   (.setSSLParameters param))]
      (SslHandler. engine))))

(defn tcp-connect
  [ch-pair opts]
  (-> (tcp/client opts)
      (deferred->ch
       (fn [stream]
         (connect-ch-pair ch-pair stream)))))

(defn ws-connect
  [ch-pair uri opts]
  (-> (ws/websocket-connection uri opts)
      (deferred->ch
       (fn [stream]
         (connect-ch-pair ch-pair stream)))))

(defmulti connect
  (fn [_ch-pair opts] (:type opts)))

(defmethod connect :tcp [ch-pair opts]
  (let [{:keys [host port tls? tls-opts] :or {tls? false}} opts
        tcp-opts (cond-> {:host host :port port :ssl? tls?}
                   tls? (assoc :ssl-context (->tls-context tls-opts)))]
    (-> ch-pair
        (tcp-connect tcp-opts))))

(defmethod connect :ws [ch-pair opts]
  (let [{:keys [host port http-path http-host tls? tls-opts] :or {http-path "/" tls? false}} opts
        scheme (if tls? "wss" "ws")
        uri (str (URI. scheme nil host port http-path nil nil))
        headers (cond-> {}
                  (some? http-host) (assoc :host http-host))
        ws-opts (cond-> {:headers headers}
                  tls? (assoc :ssl-context (->tls-context tls-opts)))]
    (-> ch-pair
        (ws-connect uri ws-opts))))

(comment
  (require '[clj-bytes.core :as b])
  (a/go
    (when-let [[ich och] (a/<! (-> [(a/chan 1024) (a/chan 1024)]
                                   (connect {:type :tcp :host "www.baidu.com" :port 80})))]
      (when (a/>! och (b/of-str "GET / HTTP/1.1\r\nHost: www.baidu.com\r\n\r\n"))
        (when-let [res (a/<! ich)]
          (println (b/str res))))))
  (a/go
    (when-let [[ich _och] (a/<! (-> [(a/chan 1024) (a/chan 1024)]
                                    (connect {:type :ws :host "echo.websocket.org" :port 443 :tls? true})))]
      (when-let [res (a/<! ich)]
        (println res)))))

;;; start server

(defn tcp-start-server
  [handle opts]
  (-> (fn [stream _info]
        (let [ch-pair (-> [(a/chan 1024) (a/chan 1024)]
                          (connect-ch-pair stream))]
          (handle ch-pair)))
      (tcp/start-server opts)))

(defn start-server
  [handle port]
  (tcp-start-server handle {:port port}))

;;; request

(defn http-request
  [opts]
  (-> (http/request opts) deferred->ch))

(defn request
  [url]
  (a/go
    (let [resp (http-request {:url url :method :get})]
      (when (= (:status resp) 200)
        (bs/to-byte-array (:body resp))))))
