(ns vmessc.socks5
  (:require [clj-bytes.core :as b]
            [clj-bytes.struct :as st]
            [vmessc.protocols :as proto]))

;; socks5: https://www.rfc-editor.org/rfc/rfc1928
;; socks5 pwd auth: https://www.rfc-editor.org/rfc/rfc1929

;;; structs

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

(def st-rsv
  (-> st/uint8 (st/wrap-validator #(= % 0))))

(def ver->int
  {:socks5 5})

(def st-ver
  (st/enum st/uint8 ver->int))

;;;; request

(def atype->int
  ;; - IP V4 address: X'01'
  ;; - DOMAINNAME: X'03'
  ;; - IP V6 address: X'04'
  {:domain 3 :ipv4 1 :ipv6 4})

(def st-atype
  (st/enum st/uint8 atype->int))

(def st-domain-host st-str)

(defn atype->st-host
  [atype]
  ;; TODO add ipv4/6 support
  (case atype
    :domain st-domain-host))

(def st-addr
  (-> (st/key-fns
       :atype (constantly st-atype)
       :host (fn [{:keys [atype]}] (atype->st-host atype))
       :port (constantly st/uint16-be))
      (st/wrap
       (fn [[host port]] {:atype :domain :host host :port port})
       (juxt :host :port))))

(def cmd->int
  ;; - CONNECT X'01'
  ;; - BIND X'02'
  ;; - UDP ASSOCIATE X'03'
  {:connect 1 :bind 2 :udp-assoc 3})

(def st-cmd
  (st/enum st/uint8 cmd->int))

(def status->int
  ;; - X'00' succeeded
  ;; - X'01' general SOCKS server failure
  ;; - X'02' connection not allowed by ruleset
  ;; - X'03' Network unreachable
  ;; - X'04' Host unreachable
  ;; - X'05' Connection refused
  ;; - X'06' TTL expired
  ;; - X'07' Command not supported
  ;; - X'08' Address type not supported
  ;; - X'09' to X'FF' unassigned
  {:ok                  0
   :error               1
   :not-allowed         2
   :net-unreach         3
   :host-unreach        4
   :conn-refused        5
   :ttl-expired         6
   :cmd-not-supported   7
   :atype-not-supported 8})

(def st-status
  (st/enum st/uint8 status->int))

(def st-req
  (st/keys
   :ver st-ver
   :cmd st-cmd
   :rsv st-rsv
   :addr st-addr))

(def st-resp
  (st/keys
   :ver st-ver
   :res st-status
   :rsv st-rsv
   :addr st-addr))

;;;; auth

(def auth-meth->int
  ;; - X'00' NO AUTHENTICATION REQUIRED
  ;; - X'01' GSSAPI
  ;; - X'02' USERNAME/PASSWORD
  ;; - X'03' to X'7F' IANA ASSIGNED
  ;; - X'80' to X'FE' RESERVED FOR PRIVATE METHODS
  ;; - X'FF' NO ACCEPTABLE METHODS
  {:no-auth 0 :gssapi 1 :pwd 2 :no-accept 0xff})

(def st-auth-meth
  (st/enum st/uint8 auth-meth->int))

(def pwd-auth-status->int
  {:ok 0 :error 1})

(def st-pwd-auth-status
  (st/enum st/uint8 pwd-auth-status->int))

(def st-auth-meths
  (-> (st/bytes-var st/uint8)
      (st/wrap-struct
       (st/coll-of st-auth-meth))))

(def st-auth-req
  (st/keys
   :ver st-ver
   :meths st-auth-meths))

(def st-auth-resp
  (st/keys
   :ver st-ver
   :meth st-auth-meth))

(def st-pwd-auth-req
  (st/keys
   :ver st-ver
   :user st-str
   :pwd st-str))

(def st-pwd-auth-resp
  (st/keys
   :ver st-ver
   :status st-pwd-auth-status))

;;; state

;;;; client

(defn ->client-state
  "Construct socks5 client side handshake state."
  [opts]
  (let [{:keys [addr buffer auth]} opts]
    (cond-> {:stage :auth-req :addr addr :first-frame buffer :buffer (b/empty)}
      (some? auth) (assoc :auth auth))))

(defmulti client-advance
  "DOC"
  (fn [state] (:stage state)))

(defmethod client-advance :auth-req [state]
  (let [{:keys [auth]} state
        use-auth? (some? auth)
        meth (if use-auth? :pwd :no-auth)
        b (-> {:ver :socks5 :meths [meth]} (st/pack st-auth-req))
        [nb state] (-> state
                       (assoc :stage :wait-auth-resp)
                       client-advance)
        b (cond-> b
            (some? nb) (b/concat! nb))]
    [b state]))

(defmethod client-advance :wait-auth-resp [state]
  (let [{:keys [auth buffer]} state
        unpack-res (-> buffer (st/unpack st-auth-resp))]
    (if (nil? unpack-res)
      [nil state]
      (let [use-auth? (some? auth)
            [{:keys [meth]} buffer] unpack-res]
        (if-not (= meth (if use-auth? :pwd :no-auth))
          (let [ex (ex-info "invalid socks5 auth resp meth" {:reason :socks5/auth-resp.meth :meth meth})]
            [nil (assoc state :stage :error :buffer buffer :ex ex)])
          (let [stage (if use-auth? :pwd-auth-req :req)]
            (-> state
                (assoc :stage stage :buffer buffer)
                client-advance)))))))

(defmethod client-advance :pwd-auth-req [state]
  (let [{:keys [auth]} state
        [user pwd] auth
        b (-> {:ver :socks5 :user user :pwd pwd} (st/pack st-pwd-auth-req))
        [nb state] (-> state
                       (assoc :stage :wait-pwd-auth-resp)
                       client-advance)
        b (cond-> b
            (some? nb) (b/concat! nb))]
    [b state]))

(defmethod client-advance :wait-pwd-auth-resp [state]
  (let [{:keys [buffer]} state
        unpack-res (-> buffer (st/unpack st-pwd-auth-resp))]
    (if (nil? unpack-res)
      [nil state]
      (let [[{:keys [status]} buffer] unpack-res]
        (if-not (= status :ok)
          (let [ex (ex-info "invalid socks5 pwd auth resp status" {:reason :socks5/pwd-auth-resp.status :status status})]
            [nil (assoc state :stage :error :buffer buffer :ex ex)])
          (-> state
              (assoc :stage :req :buffer buffer)
              client-advance))))))

(defmethod client-advance :req [state]
  (let [{:keys [addr first-frame]} state
        b (-> {:ver :socks5 :cmd :connect :rsv 0 :addr addr} (st/pack st-req) (b/concat! first-frame))
        [nb state] (-> state
                       (assoc :stage :wait-resp)
                       client-advance)
        b (cond-> b
            (some? nb) (b/concat! nb))]
    [b state]))

(defmethod client-advance :wait-resp [state]
  (let [{:keys [buffer]} state
        unpack-res (-> buffer (st/unpack st-resp))]
    (if (nil? unpack-res)
      [nil state]
      (let [[{:keys [status]} buffer] unpack-res]
        (if-not (= status :ok)
          (let [ex (ex-info "invalid socks5 resp status" {:reason :socks5/resp.status :status status})]
            [nil (assoc state :stage :error :buffer buffer :ex ex)])
          [nil (assoc state :stage :ok :buffer buffer)])))))

(defmethod client-advance :ok [state] state)
(defmethod client-advance :error [state] state)

;;;; server

;; Structure of auths, for example:
;; {"user1" #{"pwd1" "pwd2"}
;;  "user2" #{"pwd3" "pwd4"}}

(defn ->server-state
  "Construct socks5 server side handshake state."
  [opts]
  (let [{:keys [auths]} opts]
    (cond-> {:stage :wait-auth-req :buffer (b/empty)}
      (some? auths) (assoc :auths auths))))

(defmulti server-advance
  "Advance socks5 server side handshake state, return bytes to send (or
  nil if advance completed) and new state."
  (fn [state] (:stage state)))

(defmethod server-advance :wait-auth-req [state]
  (let [{:keys [buffer auths]} state
        unpack-res (-> buffer (st/unpack st-auth-req))]
    (if (nil? unpack-res)
      [nil state]
      (let [[{:keys [meths]} buffer] unpack-res
            use-auth? (some? auths)
            meth (if use-auth? :pwd :no-auth)
            meths (set meths)]
        (if-not (contains? meths meth)
          (let [b (-> {:ver :socks5 :meth :no-accept} (st/pack st-auth-req))
                ex (ex-info "invalid socks5 auth req meths" {:reason :socks5/auth-req.meths :meths meths})]
            [b (assoc state :stage :error :buffer buffer :ex ex)])
          (let [b (-> {:ver :socks5 :meth meth} (st/pack st-auth-req))
                stage (if use-auth? :wait-pwd-auth-req :wait-req)
                [nb state] (-> state
                               (assoc :stage stage :buffer buffer)
                               server-advance)
                b (cond-> b
                    (some? nb) (b/concat! nb))]
            [b state]))))))

(defn valid-user?
  "Valid user based on auths."
  [auths [user pwd]]
  (let [pwds (get auths user)]
    (and (some? pwds) (contains? pwds pwd))))

(defmethod server-advance :wait-pwd-auth-req [state]
  (let [{:keys [buffer auths]} state
        unpack-res (-> buffer (st/unpack st-pwd-auth-req))]
    (if (nil? unpack-res)
      [nil state]
      (let [[{:keys [user pwd]} buffer] unpack-res
            auth [user pwd]]
        (if-not (valid-user? auths auth)
          (let [b (-> {:ver :socks5 :status :error} (st/pack st-pwd-auth-resp))
                ex (ex-info "invalid socks5 pwd auth req auth" {:reason :socks5/pwd-auth-req.auth :auth auth})]
            [b (assoc state :stage :error :buffer buffer :ex ex)])
          (let [b (-> {:ver :socks5 :status :ok} (st/pack st-pwd-auth-resp))
                [nb state] (-> state
                               (assoc :stage :wait-req :buffer buffer)
                               server-advance)
                b (cond-> b
                    (some? nb) (b/concat! nb))]
            [b state]))))))

(defmethod server-advance :wait-req [state]
  (let [{:keys [buffer]} state
        unpack-res (-> buffer (st/unpack st-req))]
    (if (nil? unpack-res)
      [nil state]
      (let [[{:keys [cmd addr]} buffer] unpack-res]
        (if-not (= cmd :connect)
          (let [b (-> {:ver :socks5 :status :error :rsv 0 :addr ["0.0.0.0" 0]} (st/pack st-resp))
                ex (ex-info "invalid socks5 req cmd" {:reason :socks5/req.cmd :cmd cmd})]
            [b (assoc state :stage :error :buffer buffer :ex ex)])
          (let [b (-> {:ver :socks5 :status :ok :rsv 0 :addr ["0.0.0.0" 0]} (st/pack st-resp))]
            [b (assoc state :stage :ok :buffer buffer :addr addr)]))))))

(defmethod server-advance :ok [state] [nil state])
(defmethod server-advance :error [state] [nil state])

;;; register

(defrecord Socks5HandshakeState [state]
  proto/ProxyHandshakeState
  (-handshake-advance [_ b]
    (let [state (update state :buffer b/concat! b)
          [b state] (server-advance state)]
      [b (->Socks5HandshakeState state)]))
  (-handshake-info [_]
    (case (:stage state)
      :ok (select-keys state [:addr :buffer])
      :error (throw (:ex state))
      nil)))

(defmethod proto/->proxy-handshake-state :socks5 [opts]
  (->Socks5HandshakeState (->server-state opts)))
