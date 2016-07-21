package types

// DBUser -> estructura que almacena los datos de un usuario como en la BD
type DBUser struct {
	ID       int    // identificador de usuario
	Nickname string // nombre de usuario
	Hash     []byte // hash de la contraseña
	Salt     []byte // sal para la contraseña
	PubKey   string // clave publica del usuario
	PriKey   string // clave privada del usuario
}

// AppUser -> estructura que almacena los datos de un usuario para trabajar en cliente
type AppUser struct {
	ID       int    // identificador de usuario
	Nickname string // nombre de usuario
	Hash     string // hash de la contraseña
}
