(ns vmessc.net
  (:require [clojure.core.async :as a]
            [manifold.deferred :as d]
            [manifold.stream :as s]
            [aleph.tcp :as tcp]
            [aleph.http.websocket.client :as ws])
  (:import [java.net URI]
           [javax.net.ssl SSLContext SSLParameters SNIHostName]
           [io.netty.handler.ssl SslHandler]))

;;; manifold to core.async

(defn deferred->ch
  "Convert manifold deferred to core.async channel."
  ([deferred]
   (deferred->ch deferred identity))
  ([deferred xform]
   (let [ch (a/chan)]
     (-> deferred
         (d/on-realized
          (fn [data] (a/>!! ch (xform data)))
          (fn [_error] (a/close! ch))))
     ch)))

(defn connect-ch-pair-to-stream
  "Connect manifold stream to core.async channel."
  [[ich och] stream]
  (s/connect stream ich)
  (s/connect och stream)
  [ich och])

;;; connect

(defn ->tls-context
  "Construct netty TLS context, support specify sni and alpn."
  [{:keys [sni alpn]}]
  (let [param (SSLParameters.)]
    (when (some? sni)
      (.setServerNames param (java.util.List/of (SNIHostName. sni))))
    (when (some? alpn)
      (.setApplicationProtocols param (into-array String alpn)))
    (let [engine (doto (.createSSLEngine (SSLContext/getDefault))
                   (.setSSLParameters param))]
      (SslHandler. engine))))

(defn tcp-connect
  "Connect by TCP, return a chan that return connected chan pair."
  [ch-pair opts]
  (-> (tcp/client opts)
      (deferred->ch
        (fn [stream]
          (-> ch-pair (connect-ch-pair-to-stream stream))))))

(defn ws-connect
  "Connect by WS, return a chan that return connected chan pair."
  [ch-pair uri opts]
  (-> (ws/websocket-connection uri opts)
      (deferred->ch
        (fn [stream]
          (-> ch-pair (connect-ch-pair-to-stream stream))))))

(defmulti connect
  "Connect by opts, return a chan that return connected chan pair."
  (fn [_ch-pair opts] (:type opts)))

(defmethod connect :tcp [ch-pair opts]
  (let [{:keys [host port tls? tls-opts] :or {tls? false}} opts
        tcp-opts (cond-> {:host host :port port :ssl? tls?}
                   tls? (assoc :ssl-context (->tls-context tls-opts)))]
    (-> ch-pair (tcp-connect tcp-opts))))

(defmethod connect :ws [ch-pair opts]
  (let [{:keys [host port http-path http-host tls? tls-opts] :or {http-path "/" tls? false}} opts
        scheme (if tls? "wss" "ws")
        uri (str (URI. scheme nil host port http-path nil nil))
        headers (cond-> {}
                  (some? http-host) (assoc :host http-host))
        ws-opts (cond-> {:headers headers}
                  tls? (assoc :ssl-context (->tls-context tls-opts)))]
    (-> ch-pair (ws-connect uri ws-opts))))

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
                          (connect-ch-pair-to-stream stream))]
          (handle ch-pair)))
      (tcp/start-server opts)))
