package sequence

import (
	"context"
	"database/sql"
	"github.com/gofrs/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/volatiletech/null"
	"github.com/volatiletech/sqlboiler/boil"
	"sequence/models"
	"time"
)

func CreateDatabase(fname string){
	database, err := sql.Open("sqlite3", fname)
	if err != nil{
		logger.HandleFatal(err.Error())
	}
	tx, err := database.Begin()
	if err != nil {
		logger.HandleFatal(err.Error())
	}
	query := config.createDbCommands
	for _, q := range query{
		_, err = database.Exec(q)
		if err != nil{
			logger.HandleFatal(err.Error())
		}
	}
	tx.Commit()
}

func OpenDbandSetContext()(*sql.DB, context.Context){
	// Get a handle to the SQLite database, using mattn/go-sqlite3
	db, err := sql.Open("sqlite3", config.database)
	if err != nil{
		logger.HandleFatal(err.Error())
	}
	// Configure SQLBoiler to use the sqlite database
	boil.SetDB(db)
	// Need to set a context for purposes I don't understand yet
	ctx := context.Background()     // Dark voodoo magic, https://golang.org/pkg/context/#Background
	return db, ctx
}

func GetPatternsFromDatabase(db *sql.DB, ctx context.Context) map[string]string{
	pmap := make(map[string]string)
	// This pulls 'all' of the patterns from the patterns database
	patterns, err := models.Patterns().All(ctx, db)
	if err !=nil {
		logger.DatabaseSelectFailed("patterns", "All", err.Error())
	}
	for _, p := range patterns{
		pmap[p.ID] = p.SequencePattern
	}
	return pmap
}

func GetPatternsWithExamplesFromDatabase(db *sql.DB, ctx context.Context) map[string]AnalyzerResult{
	pmap := make(map[string]AnalyzerResult)
	var patterns models.PatternSlice
	var err error
	if config.matchThresholdValue != "0"{
		patterns, err = models.Patterns(models.PatternWhere.ThresholdReached.EQ(true)).All(ctx, db)
		if err !=nil {
			logger.DatabaseSelectFailed("patterns", "Where threshold_reached=true", err.Error())
		}
	}else{
		patterns, err = models.Patterns().All(ctx, db)
		if err !=nil {
			logger.DatabaseSelectFailed("patterns", "All", err.Error())
		}
	}

	for _, p := range patterns{
		var s *models.Service
		s, err = models.Services(models.ServiceWhere.ID.EQ(p.ServiceID)).One(ctx,db)
		if err !=nil {
			logger.DatabaseSelectFailed("services", "Where id = " + p.ServiceID, err.Error())
		}
		ar := AnalyzerResult{PatternId:p.ID, Pattern:p.SequencePattern, ThresholdReached:p.ThresholdReached, DateCreated:p.DateCreated, ExampleCount:int(p.OriginalMatchCount)}
		var ex models.ExampleSlice
		ex, err = p.PatternExamples().All(ctx, db)
		if err !=nil {
			logger.DatabaseSelectFailed("examples", "All", err.Error())
		}
		for _, e := range ex{
			lr := LogRecord{Message:e.ExampleDetail, Service:s.Name}
			ar.Examples = append(ar.Examples, lr)
		}
		pmap[p.ID]=ar
	}
	return pmap
}

func GetPatternsFromDatabaseByService(db *sql.DB, ctx context.Context, sid string) map[string]AnalyzerResult{
	pmap := make(map[string]AnalyzerResult)
	// This pulls 'all' of the patterns from the patterns database
	patterns, err := models.Patterns(models.PatternWhere.ServiceID.EQ(sid)).All(ctx, db)
	if err !=nil {
		logger.DatabaseSelectFailed("patterns", "Where Serviceid = " + sid, err.Error())
	}
	for _, p := range patterns{
		ar := AnalyzerResult{Pattern:p.SequencePattern, TagPositions:p.TagPositions.String}
		pmap[p.ID] = ar
	}
	return pmap
}

func GetServicesFromDatabase(db *sql.DB, ctx context.Context) map[string]string{
	// This pulls 'all' of the services from the services table
	smap := make(map[string]string)
	services, err := models.Services().All(ctx, db)
	if err !=nil {
		logger.DatabaseSelectFailed("services", "All", err.Error())
	}
	for _, p := range services{
		smap[p.ID] = p.Name
	}
	return smap
}

func AddService(ctx context.Context, tx *sql.Tx, id string, name string){
	// This pulls 'all' of the services from the services table
	var s models.Service
	s.ID = id
	s.Name = name
	s.DateCreated = time.Now()
	err := s.Insert(ctx, tx, boil.Whitelist("id", "name", "date_created"))
	if err != nil{
		logger.DatabaseInsertFailed("service", id, err.Error())
	}
}

func AddPattern(ctx context.Context, tx *sql.Tx, result AnalyzerResult, sID string){
	tp := null.String{String:result.TagPositions, Valid:true}
	p := models.Pattern{ID:result.PatternId, SequencePattern:result.Pattern, DateCreated:time.Now(),ServiceID:sID, ThresholdReached:result.ThresholdReached,
		CumulativeMatchCount:int64(result.ExampleCount), OriginalMatchCount:int64(result.ExampleCount), DateLastMatched:time.Now(), IgnorePattern:false, TagPositions:tp}
	err := p.Insert(ctx, tx, boil.Whitelist("id", "sequence_pattern", "date_created", "threshold_reached", "service_id", "date_last_matched", "original_match_count", "cumulative_match_count", "ignore_pattern", "tag_positions"))
	if err != nil{
		logger.DatabaseInsertFailed("pattern", result.PatternId, err.Error())
	}

	//add all examples if threshold has been reached as these will have already been pruned
	//otherwise limit to max three.
	if result.ThresholdReached{
		for _, e := range result.Examples{
			id, err := uuid.NewV4()
			if err !=nil {
				logger.DatabaseInsertFailed("example", result.PatternId, err.Error())
			}
			ex := models.Example{ExampleDetail:e.Message, PatternID:result.PatternId, ID:id.String()}
			err = ex.Insert(ctx, tx, boil.Infer())
			if err != nil{
				logger.DatabaseInsertFailed("example", result.PatternId, err.Error())
			}
		}
	}else{
		prev := ""
		count := 0
		for _, e := range result.Examples{
			if prev != e.Message{
				id, err := uuid.NewV4()
				if err !=nil {
					logger.DatabaseInsertFailed("example", result.PatternId, err.Error())
				}
				ex := models.Example{ExampleDetail:e.Message, PatternID:result.PatternId, ID:id.String()}
				err = ex.Insert(ctx, tx, boil.Infer())
				if err != nil{
					logger.DatabaseInsertFailed("example", result.PatternId, err.Error())
				}
				prev = e.Message
				count++
			}
			if count >= 3{
				break
			}
		}
	}
}