CREATE TABLE "AppUsers" (
	`id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`nickname`	TEXT UNIQUE,
	`hash`	TEXT NOT NULL,
	`salt`	TEXT NOT NULL,
	`pubkey`	TEXT NOT NULL,
	`prikey`	TEXT NOT NULL,
	`connected`	INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE "Messages" (
	`id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`text`	TEXT NOT NULL,
	`sender`	INTEGER NOT NULL,
	`receiver`	INTEGER NOT NULL,
	`time`	DATETIME NOT NULL,

	FOREIGN KEY(`sender`) REFERENCES `AppUsers`,
	FOREIGN KEY(`receiver`) REFERENCES `AppUsers`
);
