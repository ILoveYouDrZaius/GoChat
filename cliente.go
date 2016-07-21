package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sds/message"
	"sds/types"
	"sds/utils"
	"time"

	"github.com/gorilla/securecookie"
)

var conn net.Conn
var je *json.Encoder
var jd *json.Decoder

var nameCookie = "Cookie"

var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

var index = template.Must(template.ParseFiles(
	"templates/_base.html",
	"templates/index.html",
))

var register = template.Must(template.ParseFiles(
	"templates/_base.html",
	"templates/register.html",
))

var chats = template.Must(template.ParseFiles(
	"templates/_base.html",
	"templates/chats.html",
))

/*********** GETS ***********/

// Manejador de la vista de inicio
func redir(w http.ResponseWriter, req *http.Request) {
	http.Redirect(w, req, "https://localhost:8095", http.StatusMovedPermanently)
}

// Manejador de la vista de inicio
func indexHandler(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.Error(w, "No encontrado", http.StatusNotFound)
		return
	}

	if checkCookie(req) {
		//Redireccionamos a la página de inicio
		http.Redirect(w, req, "/chats", http.StatusTemporaryRedirect)
	} else {
		if err := index.Execute(w, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// Manejador de la vista 'register.html'
func registerHandler(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/register" {
		http.Error(w, "No encontrado", http.StatusNotFound)
		return
	}

	if checkCookie(req) {
		// Redireccionamos a índice
		http.Redirect(w, req, "/chats", http.StatusTemporaryRedirect)
	} else {
		if err := register.Execute(w, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// Manejador de la vista de chats
func chatsHandler(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/chats" {
		http.Error(w, "No encontrado", http.StatusNotFound)
		return
	}

	if checkCookie(req) {
		if err := chats.Execute(w, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	} else {
		//Redireccionamos a la página de inicio
		http.Redirect(w, req, "/", http.StatusTemporaryRedirect)
	}
}

// Manejador de los contactos
func contactsHandler(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/getContacts" {
		http.Error(w, "No encontrado", http.StatusNotFound)
		return
	}

	if checkCookie(req) {
		var err error

		user := getUserFromCookie(req)
		serverMessage := message.ServerMsg{Action: message.CONTACTS, User: user, Message: nil}

		// Crear json mensaje para mandar al server
		err = je.Encode(&serverMessage)

		if err != nil {
			http.Error(w, "Servidor no disponible", http.StatusServiceUnavailable)
		} else {

			var users []types.AppUser

			// Obtener respuesta del server
			err = jd.Decode(&users)
			utils.CheckError(err)

			// Enviamos el objeto JSON creado
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			err = json.NewEncoder(w).Encode(users)
			utils.CheckError(err)
		}
	} else {
		//Redireccionamos a la página de inicio
		http.Error(w, "No autorizado", http.StatusUnauthorized)
	}
}

// Manejador de los contactos
func messagesHandler(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/getMessages" {
		http.Error(w, "No encontrado", http.StatusNotFound)
		return
	}

	if checkCookie(req) {
		var request message.AppMsg
		var err error

		//Obtenemos el JSON de la petición
		webDecoder := json.NewDecoder(req.Body)
		err = webDecoder.Decode(&request)
		utils.CheckError(err)

		requestUser := getUserFromCookie(req)
		msg := message.AppMsg{Sender: requestUser.Nickname, Receiver: request.Receiver, Text: "", Time: time.Now()}
		serverMessage := message.ServerMsg{Action: message.MESSAGES, User: requestUser, Message: &msg}

		// Crear json mensaje para mandar al server
		err = je.Encode(&serverMessage)

		if err != nil {
			http.Error(w, "Servidor no disponible", http.StatusServiceUnavailable)
		} else {
			var messages []message.AppMsg

			// Obtener respuesta del server
			err = jd.Decode(&messages)
			utils.CheckError(err)

			// Enviamos el objeto JSON creado
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			err = json.NewEncoder(w).Encode(messages)
			utils.CheckError(err)
		}
	} else {
		//Redireccionamos a la página de inicio
		http.Error(w, "No autorizado", http.StatusUnauthorized)
	}
}

/*********** POSTS ***********/

//Comprueba si el usuario y la contraseña introducidos son correctos
func loginHandler(w http.ResponseWriter, req *http.Request) {
	//Nos aseguramos que la petición es mediante POST
	if req.Method != "POST" {
		//Devolvemos un error 404
		http.NotFound(w, req)
		return
	}

	var response message.WebMsg
	var err error

	if conn != nil {

		// Guardamos el usuario de la petición
		var webUser types.AppUser

		//Obtenemos el JSON de la petición
		webDecoder := json.NewDecoder(req.Body)
		err = webDecoder.Decode(&webUser)
		utils.CheckError(err)

		// hash con SHA512 de la contraseña
		keyClient := sha512.Sum512([]byte(webUser.Hash))
		keyLogin := keyClient[:32] // una mitad para el login (256 bits)

		user := types.AppUser{ID: -1, Nickname: webUser.Nickname, Hash: utils.Encode64(keyLogin)}
		serverMessage := message.ServerMsg{Action: message.LOGIN, User: user, Message: nil}

		// Crear json mensaje para mandar al server
		err = je.Encode(&serverMessage)

		if err == nil {
			// Obtener respuesta del server
			err = jd.Decode(&user)
			utils.CheckError(err)

			if user.ID != -1 {
				// Creamos la cookie de sesión
				setCookie(user, w)

				response = message.WebMsg{Type: "success", Message: "Login correcto"}
			} else {
				response = message.WebMsg{Type: "error", Message: "Login incorrecto"}
			}
		} else {
			response = message.WebMsg{Type: "error", Message: "Servidor no disponible"}
		}
	} else {
		response = message.WebMsg{Type: "error", Message: "Servidor no disponible"}
	}

	// Enviamos el objeto JSON creado
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	err = json.NewEncoder(w).Encode(response)
	utils.CheckError(err)
}

// Crea un nuevo usuario
func registerUserHandler(w http.ResponseWriter, req *http.Request) {
	//Nos aseguramos que la petición es mediante POST
	if req.Method != "POST" {
		//Devolvemos un error 404
		http.NotFound(w, req)
		return
	}

	var response message.WebMsg
	var err error

	if conn != nil {

		// Usuario de la petición
		var webUser types.AppUser

		//Obtenemos el JSON de la petición
		webDecoder := json.NewDecoder(req.Body)
		err = webDecoder.Decode(&webUser)
		utils.CheckError(err)

		// hash con SHA512 de la contraseña
		keyClient := sha512.Sum512([]byte(webUser.Hash))
		keyLogin := keyClient[:32]  // una mitad para el login (256 bits)
		keyData := keyClient[32:64] // la otra para los datos (256 bits)

		// generamos un par de claves (privada, pública) para el servidor
		pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
		utils.CheckError(err)
		pkClient.Precompute() // aceleramos su uso con un precálculo

		pkJSON, err := json.Marshal(&pkClient) // codificamos con JSON
		utils.CheckError(err)

		keyPub := pkClient.Public()           // extraemos la clave pública por separado
		pubJSON, err := json.Marshal(&keyPub) // y codificamos con JSON
		utils.CheckError(err)

		var data map[string]string

		data = make(map[string]string)

		data["pubkey"] = utils.Encode64(utils.Compress(pubJSON))
		data["prikey"] = utils.Encode64(utils.Encrypt(utils.Compress(pkJSON), keyData))

		user := types.AppUser{Nickname: webUser.Nickname, Hash: utils.Encode64(keyLogin)}
		serverMessage := message.ServerMsg{Action: message.REGISTER, User: user, Message: nil, Data: data}

		// Crear json mensaje para mandar al server
		err = je.Encode(&serverMessage)

		if err == nil {

			// Obtener respuesta del server
			err = jd.Decode(&user)
			utils.CheckError(err)

			if user.ID != -1 {
				// Creamos la cookie de sesión
				setCookie(user, w)

				response = message.WebMsg{Type: "success", Message: "Registro correcto"}
			} else {
				response = message.WebMsg{Type: "error", Message: "Registro incorrecto"}
				conn.Close()
			}
		} else {
			response = message.WebMsg{Type: "error", Message: "Servidor no disponible"}
		}
	} else {
		response = message.WebMsg{Type: "error", Message: "Servidor no disponible"}
	}

	// Enviamos el objeto JSON creado
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	err = json.NewEncoder(w).Encode(response)
	utils.CheckError(err)
}

//Manejador de logout
func logoutHandler(w http.ResponseWriter, req *http.Request) {
	//Nos aseguramos que la petición es mediante POST
	if req.Method != "POST" {
		//Devolvemos un error 404
		http.NotFound(w, req)
		return
	}

	var response message.WebMsg
	var done bool
	var err error

	user := getUserFromCookie(req)
	serverMessage := message.ServerMsg{Action: message.LOGOUT, User: user, Message: nil}

	// Crear json mensaje para mandar al server
	err = je.Encode(&serverMessage)

	if err != nil {
		http.Error(w, "Servidor no disponible", http.StatusServiceUnavailable)
	} else {

		// Obtener respuesta del server
		err = jd.Decode(&done)
		utils.CheckError(err)

		if done {
			clearSession(w)

			response = message.WebMsg{Type: "success", Message: "Logout correcto"}
		} else {
			response = message.WebMsg{Type: "error", Message: "Logout incorrecto"}
		}

		// Enviamos el objeto JSON creado
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		err = json.NewEncoder(w).Encode(response)
		utils.CheckError(err)
	}
}

//Manejador de envío de mensajes
func sendMessageHandler(w http.ResponseWriter, req *http.Request) {
	//Nos aseguramos que la petición es mediante POST
	if req.Method != "POST" {
		//Devolvemos un error 404
		http.NotFound(w, req)
		return
	}

	var request message.AppMsg
	var response message.WebMsg
	var sent bool
	var err error

	//Obtenemos el JSON de la petición
	webDecoder := json.NewDecoder(req.Body)
	err = webDecoder.Decode(&request)
	utils.CheckError(err)

	user := getUserFromCookie(req)

	msg := message.AppMsg{Sender: user.Nickname, Receiver: request.Receiver, Text: request.Text, Time: time.Now()}
	serverMessage := message.ServerMsg{Action: message.MESSAGE, User: user, Message: &msg}

	// Crear json mensaje para mandar al server
	err = je.Encode(&serverMessage)

	if err != nil {
		http.Error(w, "Servidor no disponible", http.StatusServiceUnavailable)
	} else {

		// Obtener respuesta del server
		err = jd.Decode(&sent)
		utils.CheckError(err)

		if sent {
			response = message.WebMsg{Type: "success", Message: "Mensaje enviado"}
		} else {
			response = message.WebMsg{Type: "error", Message: "Mensaje no enviado"}
		}

		// Enviamos el objeto JSON creado
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		err = json.NewEncoder(w).Encode(response)
		utils.CheckError(err)
	}
}

/******** AUXILIAR ********/

//Creamos la cookie
func setCookie(user types.AppUser, w http.ResponseWriter) {

	//Encriptamos el contenido
	if encoded, err := cookieHandler.Encode(nameCookie, user); err == nil {
		cookie := http.Cookie{
			Name:    nameCookie,
			Value:   encoded,
			Path:    "/",
			Expires: time.Now().Add(time.Hour),
		}
		http.SetCookie(w, &cookie)
	}
}

//Comprobamos que la cookie exista y que no haya sido manipulada
func checkCookie(req *http.Request) bool {

	if cookie, err := req.Cookie(nameCookie); err == nil {
		var cookieValue types.AppUser
		if err = cookieHandler.Decode(nameCookie, cookie.Value, &cookieValue); err == nil {
			return true
		}
	}
	return false
}

//Devolver los datos del usuario
func getUserFromCookie(req *http.Request) types.AppUser {

	var cookieUser types.AppUser

	if cookie, err := req.Cookie(nameCookie); err == nil {
		err = cookieHandler.Decode(nameCookie, cookie.Value, &cookieUser)
		utils.CheckError(err)
	}

	return cookieUser
}

//Borramos las cookies de la aplicacion
func clearSession(w http.ResponseWriter) {
	cookie := http.Cookie{
		Name:   nameCookie,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(w, &cookie)
}

func main() {
	var err error

	cli_keys, err := rsa.GenerateKey(rand.Reader, 1024) // generamos un par de claves (privada, pública) para el servidor
	utils.CheckError(err)
	cli_keys.Precompute() // aceleramos su uso con un precálculo

	conn, err = tls.Dial("tcp", "127.0.0.1:8081", &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "127.0.0.1",
	})

	utils.CheckError(err)

	var srv_pub rsa.PublicKey // contendrá la clave pública del servidor

	je = json.NewEncoder(conn) // creamos un encoder/decoder de JSON sobre la conexión
	jd = json.NewDecoder(conn)

	err = je.Encode(&cli_keys.PublicKey) // envíamos la clave pública del cliente
	utils.CheckError(err)

	err = jd.Decode(&srv_pub) // recibimos la clave pública del servidor
	utils.CheckError(err)

	cli_token := make([]byte, 48) // 384 bits (256 bits de clave + 128 bits para el IV)
	buff := make([]byte, 256)     // contendrá el token cifrado con clave pública (puede ocupar más que el texto en claro)
	rand.Read(cli_token)          // generación del token aleatorio para el cliente

	// ciframos el token del cliente con la clave pública del servidor
	enctoken, err := rsa.EncryptPKCS1v15(rand.Reader, &srv_pub, cli_token)
	utils.CheckError(err)

	err = je.Encode(&enctoken) // envíamos el token cifrado codificado con JSON
	utils.CheckError(err)

	err = jd.Decode(&buff) // leemos el token cifrado procedente del servidor
	utils.CheckError(err)

	// desciframos el token del servidor con nuestra clave privada
	session_key, err := rsa.DecryptPKCS1v15(rand.Reader, cli_keys, buff)
	utils.CheckError(err)

	// realizamos el XOR entre ambos tokens (cliente y servidor acaban con la misma clave de sesión)
	for i := 0; i < len(cli_token); i++ {
		session_key[i] ^= cli_token[i]
	}

	aesblock, err := aes.NewCipher(session_key[:32]) // cifrador en bloque AES con la clave de sesión
	utils.CheckError(err)

	aeswr := cipher.StreamWriter{S: cipher.NewCTR(aesblock, session_key[32:48]), W: conn} // un writer AES en modo CTR sobre la conexión
	aesrd := cipher.StreamReader{S: cipher.NewCTR(aesblock, session_key[32:48]), R: conn} // un reader AES en modo CTR sobre la conexión

	// redefinimos los encoder/decoder JSON para que trabajen sobre la conexión cifrada con AES
	je = json.NewEncoder(aeswr)
	jd = json.NewDecoder(aesrd)

	/** GET **/
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/chats", chatsHandler)

	http.HandleFunc("/getContacts", contactsHandler)
	http.HandleFunc("/getMessages", messagesHandler)

	/** POST **/
	http.HandleFunc("/registerUser", registerUserHandler)
	http.HandleFunc("/loginUser", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/sendMessage", sendMessageHandler)

	http.Handle("/templates/js/", http.StripPrefix("/templates/js/", http.FileServer(http.Dir("templates/js"))))

	fmt.Println("Redirecting HTTP on 8090 to HTTPS on 8095...")
	go utils.CheckError(http.ListenAndServeTLS(":8095", "tls/cert.pem", "tls/key.pem", nil))
	utils.CheckError(http.ListenAndServe(":8090", http.HandlerFunc(redir)))

	conn.Close()
}
