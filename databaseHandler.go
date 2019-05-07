package sequence

import (
	"context"
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/volatiletech/null"
	"github.com/volatiletech/sqlboiler/boil"
	"log"
	"sequence/models"
	"time"
)

func GetPatternsFromDatabase(){
	// Get a handle to the SQLite database, using mattn/go-sqlite3
	db, err := sql.Open("sqlite3", "sequence.sdb")
	defer db.Close()
	if err != nil{
		panic(err)
	}

	// Configure SQLBoiler to use the sqlite database
	boil.SetDB(db)

	// Need to set a context for purposes I don't understand yet
	ctx := context.Background()     // Dark voodoo magic, https://golang.org/pkg/context/#Background

	// This pulls 'all' of the patterns from the patterns database
	patterns, _ := models.Patterns().All(ctx, db)
	for _, p := range patterns{
		fmt.Println(p.SequencePattern)
	}
}

func GetServicesFromDatabase(){
	// Get a handle to the SQLite database, using mattn/go-sqlite3
	db, err := sql.Open("sqlite3", "sequence.sdb")
	defer db.Close()
	if err != nil{
		panic(err)
	}
	// Configure SQLBoiler to use the sqlite database
	boil.SetDB(db)

	// Need to set a context
	ctx := context.Background()

	// This pulls 'all' of the services from the services table
	services, _ := models.Services().All(ctx, db)
	for _, p := range services{
		fmt.Println(p.Name)
	}
}

func CheckServiceExists(id string) bool{
	// Get a handle to the SQLite database, using mattn/go-sqlite3
	db, err := sql.Open("sqlite3", "sequence.sdb")
	defer db.Close()
	if err != nil{
		panic(err)
	}
	// Configure SQLBoiler to use the sqlite database
	boil.SetDB(db)

	// Need to set a context
	ctx := context.Background()

	// This pulls 'all' of the services from the services table
	service, _ := models.FindService(ctx, db, id)
	if service != nil{
		return true
	}
	return false
}

func AddService(id string, name string){
	// Get a handle to the SQLite database, using mattn/go-sqlite3
	db, err := sql.Open("sqlite3", "sequence.sdb")
	defer db.Close()
	if err != nil{
		panic(err)
	}
	// Configure SQLBoiler to use the sqlite database
	boil.SetDB(db)

	// Need to set a context
	ctx := context.Background()

	// This pulls 'all' of the services from the services table
	var s models.Service
	s.ID = id
	s.Name = name
	s.DateCreated = time.Now()
	err = s.Insert(ctx, db, boil.Whitelist("id", "name", "date_created"))
	if err != nil{
		log.Fatal("Error inserting service into database, id: %s", id)
	}
}

func CheckPatternExists(id string) bool{
	// Get a handle to the SQLite database, using mattn/go-sqlite3
	db, err := sql.Open("sqlite3", "sequence.sdb")
	defer db.Close()
	if err != nil{
		panic(err)
	}
	// Configure SQLBoiler to use the sqlite database
	boil.SetDB(db)

	// Need to set a context
	ctx := context.Background()

	// This pulls 'all' of the services from the services table
	p, _ := models.FindPattern(ctx, db, id)
	if p != nil{
		return true
	}
	return false
}

func AddPattern(result AnalyzerResult, sID string, custom null.String){
	// Get a handle to the SQLite database, using mattn/go-sqlite3
	db, err := sql.Open("sqlite3", "sequence.sdb")
	defer db.Close()
	if err != nil{
		panic(err)
	}
	// Configure SQLBoiler to use the sqlite database
	boil.SetDB(db)

	// Need to set a context
	ctx := context.Background()

	// This pulls 'all' of the services from the services table
	p := models.Pattern{ID:result.PatternId, SequencePattern:result.Pattern, CustomPattern:custom, DateCreated:time.Now(),ServiceID:sID, ThresholdReached:result.ThresholdReached}
	err = p.Insert(ctx, db, boil.Whitelist("id", "sequence_pattern", "date_created", "threshold_reached", "custom_pattern", "service_id"))
	if err != nil{
		log.Fatal("Error inserting pattern into database, id: %s", result.PatternId)
	}

	//add examples
	for _, e := range result.Examples{
		ex := models.Example{ExampleDetail:e.Message, PatternID:result.PatternId}
		err = ex.Insert(ctx, db, boil.Infer())
	}

	//add initial statistics
	st := models.Statistic{PatternID:result.PatternId, CumulativeMatchCount:int64(result.ExampleCount), OriginalMatchCount:int64(result.ExampleCount), DateLastMatched:time.Now()}
	err = st.Insert(ctx, db, boil.Infer())
}