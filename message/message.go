package message

import (
	"sds/types"
	"time"
)

// AppMsg -> estructura de mensaje de aplicación
type AppMsg struct {
	ID       int
	Sender   string
	Receiver string
	Text     string
	Time     time.Time
}

// ServerMsg -> estructura de mensajes entre servidor y cliente
type ServerMsg struct {
	Action  Action
	User    types.AppUser
	Message *AppMsg
	Data    map[string]string
}

// Action -> estructura para almacenar el tipo de acción
type Action int

const (
	// REGISTER -> Acción para registrar un usuario
	REGISTER Action = iota
	// LOGIN -> Acción para autenticar un usuario
	LOGIN
	// LOGOUT -> Acción para eliminar la sesion un usuario
	LOGOUT
	// CONTACTS -> Acción para obtener los contactos de un usuario
	CONTACTS
	// MESSAGES -> Acción para recuperar los mensajes entre dos usuarios
	MESSAGES
	// MESSAGE -> Acción para almacenar un nuevo mensaje entre dos usuarios
	MESSAGE
)

// WebMsg -> estructura para almacenar los mensajes entre cliente y fachada web
type WebMsg struct {
	Type    string
	Message string
}
