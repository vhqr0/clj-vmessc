(ns vmessc.protocols)

;;; proxy

(defprotocol ProxyHandshakeState
  (-handshake-advance [this b]
    "Return bytes to send and new state.")
  (-handshake-info [this]
    "Return handshake info (or nil if not connected), a map that contains addr, buffer and optional client-xform."))

(defmulti ->proxy-handshake-state
  "Construct handshake state."
  (fn [opts] (:type opts)))

(defmulti ->proxy-connect-info
  "Return connect info (or nil if not connected), a map that contains net-opts and optional xform pair."
  (fn [_info opts] (:type opts)))
