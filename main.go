package main

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Fatal(err.Error())
	}
	defer db.Close()
	createtable(db)
	insertdata(db, "200083", "Akshat Arya")
}

func createtable(db *sql.DB) {
	creatingtable := `CREATE TABLE IF NOT EXISTS student(
		"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		"rollno" TEXT ,
		"name" TEXT ,
		unique(rollno));` //sql statement for creating table
	statement, err := db.Prepare(creatingtable)
	if err != nil {
		log.Fatal(err.Error())
	}
	statement.Exec() //executing sql statements
}

func insertdata(db *sql.DB, rollno string, name string) {
	insertingdata := `INSERT INTO student(rollno,name) VALUES (?,?)`
	statement, err := db.Prepare(insertingdata)
	statement.Exec(rollno, name)
	if err != nil {
		log.Fatalln(err.Error())
	}
}
