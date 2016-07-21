package data

import (
	"bytes"
	"database/sql"
	"os"
	"sds/message"
	"sds/types"
	"sds/utils"

	"golang.org/x/crypto/scrypt"

	// Librería para acceder a la BD
	_ "github.com/mattn/go-sqlite3"
)

const databaseLocation = "./data/database.db?cache=shared&mode=rwc"

var defaultUser = types.AppUser{ID: -1, Nickname: ""}

// CreateUsersDB -> función para poblar la base de datos
func CreateUsersDB() {
	db, err := sql.Open("sqlite3", databaseLocation)
	utils.CheckError(err)

	defer db.Close()

	// Crear la tabla usuarios
	createTable := `drop table if exists AppUsers; create table AppUsers (nickname text not null primary key, password text not null);`
	_, err = db.Exec(createTable)
	utils.CheckError(err)
}

// Init -> función para incializar la BD
func Init() {
	if _, err := os.Stat(databaseLocation); os.IsNotExist(err) {
		CreateUsersDB()
	}
}

// Create -> función para añadir un usuario a la DB
func Create(requestUser types.DBUser) (types.AppUser, error) {
	db, err := sql.Open("sqlite3", databaseLocation)
	utils.CheckError(err)

	defer db.Close()

	insert, err := db.Prepare("INSERT INTO AppUsers(nickname, hash, salt, pubkey, prikey) VALUES(?, ?, ?, ?, ?)")
	utils.CheckError(err)

	defer insert.Close()

	_, err = insert.Exec(requestUser.Nickname, requestUser.Hash, requestUser.Salt, requestUser.PubKey, requestUser.PriKey)

	if err == nil {
		inserted, err := Get(requestUser.Nickname)
		utils.CheckError(err)

		return types.AppUser{ID: inserted.ID, Nickname: inserted.Nickname, Hash: inserted.Hash}, err
	}

	return defaultUser, nil
}

// Get -> función para obtner un usuario a partir de su nickname
func Get(nickname string) (types.AppUser, error) {
	db, err := sql.Open("sqlite3", databaseLocation)
	utils.CheckError(err)

	defer db.Close()

	get, err := db.Prepare("SELECT id, nickname, hash FROM AppUsers WHERE nickname = ?")
	utils.CheckError(err)

	defer get.Close()

	user := defaultUser
	err = get.QueryRow(nickname).Scan(&user.ID, &user.Nickname, &user.Hash)

	return user, err
}

// DoLogin -> función para comprobar credenciales de un usuario
func DoLogin(requestUser types.AppUser) (types.AppUser, error) {
	db, err := sql.Open("sqlite3", databaseLocation)
	utils.CheckError(err)

	defer db.Close()

	get, err := db.Prepare("SELECT id, nickname, hash, salt FROM AppUsers WHERE nickname = ?")
	utils.CheckError(err)

	defer get.Close()

	var user types.DBUser
	err = get.QueryRow(requestUser.Nickname).Scan(&user.ID, &user.Nickname, &user.Hash, &user.Salt)

	if err == nil {
		password := utils.Decode64(requestUser.Hash)
		hash, _ := scrypt.Key(password, user.Salt, 16384, 8, 1, 32)
		if bytes.Compare(user.Hash, hash) == 0 {
			return types.AppUser{ID: user.ID, Nickname: user.Nickname}, nil
		}
	}

	return defaultUser, err
}

// GetContactsOf -> función para recuperar los contactos de un usuario
func GetContactsOf(nickname string) ([]types.AppUser, error) {
	db, err := sql.Open("sqlite3", databaseLocation)
	utils.CheckError(err)

	defer db.Close()

	get, err := db.Prepare("select ID, Nickname from AppUsers WHERE Nickname NOT LIKE ?")
	utils.CheckError(err)

	defer get.Close()

	rows, err := get.Query(nickname)
	utils.CheckError(err)

	//Almacenará los nombres de los archivos leidos de la BD
	var contacts []types.AppUser
	// Inicializamos para que si no hay valores devuelva lista vacía
	contacts = []types.AppUser{}

	//Variable auxiliar para guardar las iteraciones query
	var tmpContact types.AppUser

	//Iteramos a través de la query realizada
	for rows.Next() {

		//Guardamos cada resultado en una variable temporal
		err = rows.Scan(&tmpContact.ID, &tmpContact.Nickname)
		utils.CheckError(err)

		//Añadimos los valores de la variable temporal de resultados
		contacts = append(contacts, tmpContact)
	}

	return contacts, err
}

// GetMessagesBetween -> función para recuperar los mensages entre usuarios
func GetMessagesBetween(sender string, receiver string) ([]message.AppMsg, error) {
	db, err := sql.Open("sqlite3", databaseLocation)
	utils.CheckError(err)

	defer db.Close()

	get, err := db.Prepare("select * from Messages WHERE Sender=? AND Receiver=? UNION select * from Messages WHERE Sender=? AND Receiver=? ORDER BY time;")
	utils.CheckError(err)

	defer get.Close()

	rows, err := get.Query(sender, receiver, receiver, sender)
	utils.CheckError(err)

	//Almacenará los nombres de los mensajes leidos de la BD
	var messages []message.AppMsg
	// Inicializamos para que si no hay valores devuelva lista vacía
	messages = []message.AppMsg{}

	//Variable auxiliar para guardar las iteraciones query
	var tempMsg message.AppMsg

	//Iteramos a través de la query realizada
	for rows.Next() {
		//Guardamso cada resultado en una variable temporal
		err = rows.Scan(&tempMsg.ID, &tempMsg.Text, &tempMsg.Sender, &tempMsg.Receiver, &tempMsg.Time)
		utils.CheckError(err)

		//Añadimos los valores de la variable temporal de resultados
		messages = append(messages, tempMsg)
	}

	return messages, err
}

// SendMessage -> función para almacenar mensajes enviados entre usuarios
func SendMessage(msg *message.AppMsg) bool {
	db, err := sql.Open("sqlite3", databaseLocation)
	utils.CheckError(err)

	defer db.Close()

	insert, err := db.Prepare("INSERT INTO Messages(text, sender, receiver, time) VALUES(?, ?, ?, ?)")
	utils.CheckError(err)

	defer insert.Close()

	result, err := insert.Exec(msg.Text, msg.Sender, msg.Receiver, msg.Time)
	utils.CheckError(err)

	if num, err := result.RowsAffected(); err == nil {
		if num == 1 {
			return true
		}
	}

	return false
}

// GetPubKey -> función para almacenar mensajes enviados entre usuarios
func GetPubKey(receiver string) string {
	var pubkey string

	db, err := sql.Open("sqlite3", databaseLocation)
	utils.CheckError(err)

	defer db.Close()

	get, err := db.Prepare("SELECT pubkey FROM AppUsers WHERE nickname = ?")
	utils.CheckError(err)

	defer get.Close()

	err = get.QueryRow(receiver).Scan(&pubkey)

	return pubkey
}
