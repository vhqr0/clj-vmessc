(ns vmessc.server
  (:require [clojure.string :as str]
            [clojure.core.async :as a]
            [clj-bytes.core :as b]
            [vmessc.net :as net]
            [vmessc.protocols :as proto]))

(defmethod proto/->proxy-connect-info :block [_info _opts])

(defmethod proto/->proxy-connect-info :direct [{:keys [addr]} _opts]
  (let [[host port] addr]
    {:net-opts {:type :tcp :host host :port port}}))

(defn proxy-connect
  [info opts]
  (a/go
    (when-let [{:keys [net-opts xform-pair]} (proto/->proxy-connect-info info opts)]
      (let [ch-pair (if (nil? xform-pair)
                      [(a/chan 1024 (remove b/empty?))
                       (a/chan 1024 (remove b/empty?))]
                      (let [[ixform oxform] xform-pair]
                        [(a/chan 1024 (remove b/empty?) ixform (remove b/empty?))
                         (a/chan 1024 (remove b/empty?) oxform (remove b/empty?))]))]
        (a/<! (-> ch-pair (net/connect net-opts)))))))

(defmulti connect
  (fn [_info opts] (:type opts)))

(defmethod connect :proxy [info {:keys [name proxy-opts]}]
  (let [ch (proxy-connect info proxy-opts)]
    [[name] ch]))

(defmethod connect :rand-dispatch [info {:keys [name sub-opts]}]
  (let [[path ch] (connect info (rand-nth sub-opts))]
    [(vec (cons name path)) ch]))

(defn match-tag
  [host tag-map]
  (when (not (str/blank? host))
    (if-let [tag (get tag-map host)]
      tag
      (when-let [host (second (str/split host #"\." 2))]
        (recur host tag-map)))))

^:rct/test
(comment
  (match-tag "google.com" {"google.com" :proxy}) ; => :proxy
  (match-tag "www.google.com" {"google.com" :proxy}) ; => :proxy
  (match-tag "www.a.google.com" {"google.com" :proxy}) ; => :proxy
  (match-tag "ads.google.com" {"google.com" :proxy "ads.google.com" :block}) ; => :block
  (match-tag "baidu.com" {"google.com" :proxy}) ; => nil
  )

(defn info->tag
  [tag-map {:keys [addr]}]
  (let [[host _port] addr]
    (match-tag host tag-map)))

(defmethod connect :tag-dispatch [info {:keys [name tag-map default-tag sub-opts] :or {default-tag :direct}}]
  (let [tag (or (info->tag info tag-map) default-tag)
        opts (get sub-opts tag)
        [path ch] (connect info opts)]
    [(vec (cons name path)) ch]))

(defmulti log
  (fn [_info opts] (:type opts)))

(defmethod log :console
  [{:keys [addr path]} _opts]
  (println "connect to" addr "via" path))

(defn handshake
  [[ich och] state]
  (a/go-loop [state state]
    (or (proto/-handshake-info state)
        (when-let [b (a/<! ich)]
          (let [[b state] (proto/-handshake-advance state b)]
            (when (or (b/empty? b) (a/>! och b))
              (recur state)))))))

(defn handle
  [client {:keys [log-opts handshake-opts connect-opts]}]
  (let [state (proto/->proxy-handshake-state handshake-opts)]
    (a/go
      (when-let [{:keys [buffer client-xform] :as info} (a/<! (handshake client state))]
        (let [client (cond-> client
                       (some? client-xform) client-xform)
              [path server-ch] (connect info connect-opts)
              info (assoc info :path path)]
          (log info log-opts)
          (when-let [server (a/<! server-ch)]
            (when (or (b/empty? buffer) (a/>! (second server) buffer))
              (a/pipe (first client) (second server))
              (a/pipe (first server) (second client)))))))))

(defn start-server
  [{:keys [port] :as ctx}]
  (net/start-server #(handle % ctx) port))
