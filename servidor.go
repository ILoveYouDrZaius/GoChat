package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sds/data"
	"sds/message"
	"sds/types"
	"sds/utils"
	"sync"
	"time"

	"github.com/pusher/pusher-http-go"

	"golang.org/x/crypto/scrypt"
	// Librería para envío de notificaciones a frontend
)

var conn net.Conn
var je *json.Encoder
var pusherClient pusher.Client

var mutex sync.RWMutex
var connections map[net.Addr]types.AppUser

func login(requestUser types.AppUser) {
	var user types.AppUser
	var err error

	if user, err = data.DoLogin(requestUser); err == nil {
		mutex.Lock()
		connections[conn.RemoteAddr()] = user
		mutex.Unlock()
	}

	err = je.Encode(&user)
	utils.CheckError(err)
}

func logout(requestUser types.AppUser) {
	mutex.Lock()
	if connections[conn.RemoteAddr()].Nickname == requestUser.Nickname {
		delete(connections, conn.RemoteAddr())
	}
	mutex.Unlock()

	err := je.Encode(true)
	utils.CheckError(err)
}

func reg(msg message.ServerMsg) {
	u := types.DBUser{}
	u.Nickname = msg.User.Nickname                                                 // nombre
	u.Salt = make([]byte, 16)                                                      // sal (16 bytes == 128 bits)
	rand.Read(u.Salt)                                                              // la sal es aleatoria
	u.Hash, _ = scrypt.Key(utils.Decode64(msg.User.Hash), u.Salt, 16384, 8, 1, 32) // "hasheamos" la contraseña con scrypt
	u.PriKey = msg.Data["prikey"]                                                  // clave privada
	u.PubKey = msg.Data["prikey"]                                                  // clave pública

	user, err := data.Create(u)
	utils.CheckError(err)

	if err == nil {
		mutex.Lock()
		connections[conn.RemoteAddr()] = user
		mutex.Unlock()

		// Enviar notificacion push para actualizar cliente web
		data := map[string]string{"Contact": u.Nickname}
		pusherClient.Trigger("Contacts", "contacts", data)
	}

	err = je.Encode(&user)
	utils.CheckError(err)
}

func contacts(msg message.ServerMsg) {
	var users []types.AppUser
	var err error

	users, err = data.GetContactsOf(msg.User.Nickname)
	utils.CheckError(err)

	err = je.Encode(&users)
	utils.CheckError(err)
}

func messages(msg *message.AppMsg) {
	var messages []message.AppMsg
	var err error

	messages, err = data.GetMessagesBetween(msg.Sender, msg.Receiver)
	utils.CheckError(err)

	err = je.Encode(&messages)
	utils.CheckError(err)
}

func sendMessage(msg *message.AppMsg) {
	var done bool
	var err error

	done = data.SendMessage(msg)
	utils.CheckError(err)

	// Enviar notificacion push para actualizar cliente web
	data := map[string]string{"Sender": msg.Sender, "Text": msg.Text}
	pusherClient.Trigger(msg.Receiver, "notifications", data)

	err = je.Encode(&done)
	utils.CheckError(err)
}

func main() {

	pusherClient = pusher.Client{
		AppId:   "214457",
		Key:     "4076408f199075cfde1f",
		Secret:  "fab9f36c72d64dab9698",
		Cluster: "eu",
		Secure:  true,
	}

	connections = make(map[net.Addr]types.AppUser)

	srv_keys, err := rsa.GenerateKey(rand.Reader, 1024) // generamos un par de claves (privada, pública) para el servidor
	utils.CheckError(err)
	srv_keys.Precompute() // aceleramos su uso con un precálculo

	cert, err := tls.LoadX509KeyPair("tls/cert.pem", "tls/key.pem")
	if err != nil {
		fmt.Println("Error cargando certificado. ", err)
	}

	config := tls.Config{Certificates: []tls.Certificate{cert}}

	now := time.Now()
	config.Time = func() time.Time { return now }
	config.Rand = rand.Reader

	ln, err := tls.Listen("tcp", "localhost:8081", &config) // escucha en espera de conexión
	utils.CheckError(err)

	defer ln.Close() // nos aseguramos que cerramos las conexiones aunque el programa falle

	fmt.Println("Listening on 8081...")

	for { // búcle infinito, se sale con ctrl+c
		conn, err = ln.Accept() // para cada nueva petición de conexión
		utils.CheckError(err)

		go func() { // lanzamos un cierre (lambda, función anónima) en concurrencia

			_, port, err := net.SplitHostPort(conn.RemoteAddr().String()) // obtenemos el puerto remoto para identificar al cliente (decorativo)
			utils.CheckError(err)

			fmt.Println("[", conn.RemoteAddr(), "] --> CONNECTED")

			var cli_pub rsa.PublicKey // contendrá la clave pública del cliente

			je = json.NewEncoder(conn) // creamos un encoder/decoder de JSON sobre la conexión
			jd := json.NewDecoder(conn)

			err = je.Encode(&srv_keys.PublicKey) // envíamos la clave pública del servidor
			utils.CheckError(err)

			err = jd.Decode(&cli_pub) // recibimos la clave pública del cliente
			utils.CheckError(err)

			srv_token := make([]byte, 48) // 384 bits (256 bits de clave + 128 bits para el IV)
			buff := make([]byte, 256)     // contendrá el token cifrado con clave pública (puede ocupar más que el texto en claro)
			rand.Read(srv_token)          // generación del token aleatorio para el servidor

			// ciframos el token del servidor con la clave pública del cliente
			enctoken, err := rsa.EncryptPKCS1v15(rand.Reader, &cli_pub, srv_token)
			utils.CheckError(err)

			err = je.Encode(&enctoken) // envíamos el token cifrado codificado con JSON
			utils.CheckError(err)

			err = jd.Decode(&buff) // leemos el token cifrado procedente del cliente
			utils.CheckError(err)

			// desciframos el token del cliente con nuestra clave privada
			session_key, err := rsa.DecryptPKCS1v15(rand.Reader, srv_keys, buff)
			utils.CheckError(err)

			// realizamos el XOR entre ambos tokens (cliente y servidor acaban con la misma clave de sesión)
			for i := 0; i < len(srv_token); i++ {
				session_key[i] ^= srv_token[i]
			}

			aesblock, err := aes.NewCipher(session_key[:32]) // cifrador en bloque AES con la clave de sesión
			utils.CheckError(err)

			aeswr := cipher.StreamWriter{S: cipher.NewCTR(aesblock, session_key[32:48]), W: conn} // un writer AES en modo CTR sobre la conexión
			aesrd := cipher.StreamReader{S: cipher.NewCTR(aesblock, session_key[32:48]), R: conn} // un reader AES en modo CTR sobre la conexión

			// redefinimos los encoder/decoder JSON para que trabajen sobre la conexión cifrada con AES
			je = json.NewEncoder(aeswr)
			scanner := bufio.NewScanner(aesrd) // el scanner nos permite trabajar con la entrada línea a línea (por defecto)

			for scanner.Scan() { // escaneamos la conexión
				text := scanner.Text()

				fmt.Println("[", port, "]: ", text) // mostramos el mensaje del cliente

				// Guardamos el usuario de la petición
				var messagePetition message.ServerMsg

				jsonBytes := []byte(text)
				json.Unmarshal(jsonBytes, &messagePetition)

				switch messagePetition.Action {
				case message.REGISTER:
					reg(messagePetition)
				case message.LOGIN:
					login(messagePetition.User)
				case message.LOGOUT:
					logout(messagePetition.User)
				case message.CONTACTS:
					contacts(messagePetition)
				case message.MESSAGES:
					messages(messagePetition.Message)
				case message.MESSAGE:
					sendMessage(messagePetition.Message)
				default:
					fmt.Fprintln(conn, "Unrecognized action")
				}
			}

			delete(connections, conn.RemoteAddr())
			conn.Close() // cerramos al finalizar el cliente (EOF se envía con ctrl+d o ctrl+z según el sistema)
			fmt.Println("[", port, "] --> DISCONNECTED")
		}()
	}
}
