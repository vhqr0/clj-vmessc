(ns vmessc.socks5
  (:require [clj-bytes.core :as b]
            [clj-bytes.struct :as st]
            [vmessc.protocols :as proto]))

;;; structs

(def st-rsv
  (-> st/uint8 (st/wrap-validator #(= % 0))))

(def st-str
  (-> (st/bytes-var st/uint8)
      st/wrap-str))

^:rct/test
(comment
  (-> (b/concat! (b/of-int 5 :uint8) (b/of-str "hello"))
      (st/unpack st-str)
      first)
  ;; => "hello"
  )

(def ver->int
  {:socks5 5})

(def st-ver
  (st/enum st/uint8 ver->int))

(def cmd->int
  {:connect 1})

(def st-cmd
  (st/enum st/uint8 cmd->int))

(def res->int
  {:ok 0})

(def st-res
  (st/enum st/uint8 res->int))

(def atype->int
  {:domain 3})

(def st-atype
  (st/enum st/uint8 atype->int))

(def st-domain-host st-str)

(def st-addr
  (-> (st/key-fns
       :atype (constantly st-atype)
       :host (fn [{:keys [atype]}]
               (case atype
                 :domain st-domain-host))
       :port (constantly st/uint16-be))
      (st/wrap
       (fn [[host port]] {:atype :domain :host host :port port})
       (juxt :host :port))))

(def meth->int
  {:no-auth 0})

(def st-meth
  (st/enum st/uint8 meth->int))

(def st-meths
  (-> (st/bytes-var st/uint8)
      (st/wrap-struct
       (st/coll-of st-meth))
      (st/wrap-validator seq)))

(def st-auth-req
  (st/keys
   :ver st-ver
   :meths st-meths))

(def st-auth-rep
  (st/keys
   :ver st-ver
   :meth st-meth))

(def st-req
  (st/keys
   :ver st-ver
   :cmd st-cmd
   :rsv st-rsv
   :addr st-addr))

(def st-rep
  (st/keys
   :ver st-ver
   :res st-res
   :rsv st-rsv
   :addr st-addr))

;;; state

(defn ->state
  "Construct socks5 handshake state."
  []
  {:stage :wait-auth-req :buffer (b/empty)})

(defmulti advance
  "Advance socks5 handshake state, return bytes to send (or nil if
  advance completed) and new state."
  (fn [state] (:stage state)))

(defmethod advance :wait-auth-req [state]
  (let [{:keys [buffer]} state]
    (if-let [[_ buffer] (-> buffer (st/unpack st-auth-req))]
      (let [rep (-> {:ver :socks5 :meth :no-auth} (st/pack st-auth-req))]
        [rep (assoc state :stage :wait-req :buffer buffer)])
      [nil state])))

(defmethod advance :wait-req [state]
  (let [{:keys [buffer]} state]
    (if-let [[{:keys [addr]} buffer] (-> buffer (st/unpack st-req))]
      (let [rep (-> {:ver :socks5 :res :ok :rsv 0 :addr ["0.0.0.0" 0]} (st/pack st-rep))]
        [rep (assoc state :stage :connected :buffer buffer :addr addr)])
      [nil state])))

(defmethod advance :connected [state]
  [nil state])

(defn advance-recur
  "Recursive advance socks5 handshake state until advance completed,
  return bytes to send and new state."
  [state b]
  (let [state (update state :buffer b/concat! b)]
    (loop [bs [] state state]
      (let [[b state] (advance state)]
        (if (nil? b)
          [(b/join! bs) state]
          (recur (conj bs b) state))))))

(defrecord Socks5HandshakeState [state]
  proto/ProxyHandshakeState
  (-handshake-advance [_ b]
    (let [[b state] (advance-recur state b)]
      [b (->Socks5HandshakeState state)]))
  (-handshake-info [_]
    (when (= (:stage state) :connected)
      (select-keys state [:addr :buffer]))))

(defmethod proto/->proxy-handshake-state :socks5 [_opts]
  (->Socks5HandshakeState (->state)))
