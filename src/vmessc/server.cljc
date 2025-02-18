(ns vmessc.server
  (:require [clojure.string :as str]
            [clojure.core.async :as a]
            [clj-bytes.core :as b]
            [vmessc.crypto :as crypto]
            [vmessc.net :as net]
            [vmessc.protocols :as proto]))

;;; common

(defmethod proto/->proxy-connect-info :block [_info _opts])

(defmethod proto/->proxy-connect-info :direct [{:keys [addr]} _opts]
  (let [[host port] addr]
    {:net-opts {:type :tcp :host host :port port}}))

;;; connect

(defmulti connect
  "Connect to server as proxy request's info."
  (fn [_info opts] (:type opts)))

;;;; proxy

(defn proxy-connect
  "Connect via proxy server."
  [info opts]
  (a/go
    (when-let [{:keys [net-opts xform-pair]} (proto/->proxy-connect-info info opts)]
      (let [ch-pair (if (nil? xform-pair)
                      [(a/chan 1024 (remove b/empty?))
                       (a/chan 1024 (remove b/empty?))]
                      (let [[ixform oxform] xform-pair]
                        [(a/chan 1024 (comp (remove b/empty?) ixform (remove b/empty?)))
                         (a/chan 1024 (comp (remove b/empty?) oxform (remove b/empty?)))]))]
        (a/<! (-> ch-pair (net/connect net-opts)))))))

(defmethod connect :proxy [info {:keys [name proxy-opts]}]
  (let [ch (proxy-connect info proxy-opts)]
    [[name] ch]))

;;;; rand-dispatch

(defmethod connect :rand-dispatch [info {:keys [name sub-opts]}]
  (let [[path ch] (connect info (rand-nth sub-opts))]
    [(vec (cons name path)) ch]))

;;;; tag-dispatch

(defn match-host-tag
  "Match host's tag in tag-map."
  [host tag-map]
  (when (not (str/blank? host))
    (if-let [tag (get tag-map host)]
      tag
      (when-let [host (second (str/split host #"\." 2))]
        (recur host tag-map)))))

^:rct/test
(comment
  (match-host-tag "google.com" {"google.com" :proxy}) ; => :proxy
  (match-host-tag "www.google.com" {"google.com" :proxy}) ; => :proxy
  (match-host-tag "www.a.google.com" {"google.com" :proxy}) ; => :proxy
  (match-host-tag "ads.google.com" {"google.com" :proxy "ads.google.com" :block}) ; => :block
  (match-host-tag "baidu.com" {"google.com" :proxy}) ; => nil
  )

(defn match-info-tag
  "Match proxy request info's tag. in tag-map"
  [info tag-map]
  (-> info (get-in [:addr 0]) (match-host-tag tag-map)))

(defmethod connect :tag-dispatch [info {:keys [name tag-map default-tag sub-opts] :or {default-tag :direct}}]
  (let [tag (or (match-info-tag info tag-map) default-tag)
        opts (get sub-opts tag)
        [path ch] (connect info opts)]
    [(vec (cons name path)) ch]))

;;; log

(defmulti log
  "Log msg."
  (fn [_msg opts] (:type opts)))

(defmethod log :console [msg _opts]
  (let [now (-> (crypto/now) crypto/inst-fmt)]
    (-> msg (assoc :now now) prn)))

;;; handle

(defn handshake
  "Do handshake with proxy handshake state."
  [[ich och] state]
  (a/go-loop [state state]
    (if-let [info (proto/-handshake-info state)]
      info
      (when-let [b (a/<! ich)]
        (let [[b state] (proto/-handshake-advance state b)]
          (when (or (b/empty? b) (a/>! och b))
            (recur state)))))))

(defn handle
  "Do handle proxy request."
  [client {:keys [log-opts handshake-opts connect-opts]}]
  (let [state (proto/->proxy-handshake-state handshake-opts)]
    (a/go
      (when-let [{:keys [addr buffer client-xform] :as info}
                 (a/<! (handshake client state))]
        (let [client (cond-> client
                       (some? client-xform) client-xform)
              [path server-ch] (connect info connect-opts)]
          (-> {:level :info :type :connect :to addr :via path} (log log-opts))
          (when-let [server (a/<! server-ch)]
            (when (or (b/empty? buffer) (a/>! (second server) buffer))
              (a/pipe (first client) (second server))
              (a/pipe (first server) (second client)))))))))

;;; server

(defn start-server
  "Start a proxy server."
  [{:keys [log-opts port] :as ctx}]
  (-> {:level :info :type :start-server :port port} (log log-opts))
  (-> #(handle % ctx) (net/tcp-start-server {:port port})))
