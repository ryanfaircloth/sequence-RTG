package sequence

import (
	"context"
	"database/sql"
	"github.com/gofrs/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/volatiletech/null"
	"github.com/volatiletech/sqlboiler/boil"
	"github.com/volatiletech/sqlboiler/queries"
	"github.com/volatiletech/sqlboiler/queries/qm"
	"gitlab.in2p3.fr/cc-in2p3-system/sequence/models"
	"strconv"
	"strings"
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

func UpdateDatabase(){
	database, err := sql.Open("sqlite3", config.database)
	if err != nil{
		logger.HandleFatal(err.Error())
	}
	tx, err := database.Begin()
	if err != nil {
		logger.HandleFatal(err.Error())
	}
	query := config.updateDbCommands
	for _, q := range query{
		_, err = database.Exec(q)
		if err != nil{
			logger.HandleFatal(err.Error())
		}
	}
	tx.Commit()
}

func PurgePatternsfromDatabase(threshold int64) int64 {
	database, ctx := OpenDbandSetContext()
	tx, err := database.Begin()
	if err != nil {
		logger.HandleError(err.Error())
	}
	patterns, _ := models.Patterns(models.PatternWhere.CumulativeMatchCount.LT(threshold)).All(ctx, tx)
	for _, pat := range patterns{
		svc, err := pat.ServiceIdServices().All(ctx, tx)
		if err != nil {
			logger.HandleError(err.Error())
		}
		for _, s := range svc{
			pat.RemoveServiceIdServices(ctx, tx, s)
		}
		pat.PatternExamples().DeleteAll(ctx, tx)
	}
	if len(patterns)> 0{
		rowsAff, err := patterns.DeleteAll(ctx, tx)
		if err != nil {
			logger.HandleFatal(err.Error())
		}
		tx.Commit()
		return rowsAff
	}
	return 0
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

//this is for the output to files
func GetPatternsWithExamplesFromDatabase(db *sql.DB, ctx context.Context) (map[string]AnalyzerResult, string){
	var (
		patterns models.PatternSlice
		err error
		top5 string
	)
	pmap := make(map[string]AnalyzerResult)
	if config.matchThresholdValue != "0"{
		var threshold int64
		if config.matchThresholdType == "count"{
			threshold, _ = strconv.ParseInt(config.matchThresholdValue, 10, 64)
		}else{
			total := getRecordProcessed(db, ctx)
			threshold = int64(GetThreshold(total))
		}
		patterns, err = models.Patterns(models.PatternWhere.CumulativeMatchCount.GTE(threshold) , qm.OrderBy(models.PatternColumns.CumulativeMatchCount + " DESC")).All(ctx, db)
		if err !=nil {
			logger.DatabaseSelectFailed("patterns", "Where threshold_reached=true", err.Error())
		}
	}else{
		patterns, err = models.Patterns(qm.OrderBy(models.PatternColumns.CumulativeMatchCount + " DESC")).All(ctx, db)
		if err !=nil {
			logger.DatabaseSelectFailed("patterns", "All", err.Error())
		}
	}

	//get the top 5 for logging
	if len(patterns) >= 5{
		p5 := patterns[:5]
		for _, d := range p5{
			top5 += d.ID + ", "
		}
	}else{
		for _, d := range patterns{
			top5 += d.ID + ", "
		}
	}


	for _, p := range patterns{
		ar := AnalyzerResult{PatternId:p.ID, Pattern:p.SequencePattern, DateCreated:p.DateCreated, DateLastMatched:p.DateLastMatched, ExampleCount:int(p.CumulativeMatchCount), TagPositions:p.TagPositions.String}
		svcs, err := p.ServiceIdServices().All(ctx, db)
		if err !=nil {
			logger.DatabaseSelectFailed("services", "Where id = " + p.ID, err.Error())
		}
		ar.Services = svcs
		var ex models.ExampleSlice
		ex, err = p.PatternExamples().All(ctx, db)
		if err !=nil {
			logger.DatabaseSelectFailed("examples", "All", err.Error())
		}
		for _, e := range ex{
			s, _ := e.Service().One(ctx, db)
			lr := LogRecord{Message:e.ExampleDetail, Service:s.Name}
			ar.Examples = append(ar.Examples, lr)
		}
		pmap[p.ID]=ar
	}
	return pmap, top5
}

// this sums the cumulative pattern couln in the pattern table
func getRecordProcessed(db *sql.DB, ctx context.Context) int{
	// Custom struct for selecting a subset of data
	type Info struct {
		MessageSum int `boil:"message_sum"`
	}

	var info Info

	err := queries.Raw("SELECT sum(cumulative_match_count) as message_sum FROM Patterns", 5).Bind(ctx, db, &info)
	if err !=nil {
		logger.DatabaseSelectFailed("patterns", "sum(cumulative_match_count)", err.Error())
	}
	return info.MessageSum
}

//this is for the parser
func GetPatternsFromDatabaseByService(db *sql.DB, ctx context.Context, sid string) map[string]AnalyzerResult{
	pmap := make(map[string]AnalyzerResult)
	// This pulls 'all' of the patterns from the patterns database
	svc, err := models.Services(models.ServiceWhere.ID.EQ(sid)).One(ctx, db)
	if err !=nil {
		if err.Error() != "sql: no rows in result set"{
			logger.DatabaseSelectFailed("services", "Where Serviceid = " + sid, err.Error())
		}
	} else {
		patterns, err := svc.PatternIdPatterns().All(ctx, db)
		if err !=nil {
			logger.DatabaseSelectFailed("patterns", "Where Serviceid = " + sid, err.Error())
		}
		for _, p := range patterns{
			ar := AnalyzerResult{Pattern:p.SequencePattern, TagPositions:p.TagPositions.String}
			pmap[p.ID] = ar
		}
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
func AddPattern(ctx context.Context, tx *sql.Tx, result AnalyzerResult, tr int) bool {
	if tr > result.ExampleCount{
		//do not add the pattern
		return false
	}
	tp := null.String{String:result.TagPositions, Valid:true}
	p := models.Pattern{ID:result.PatternId, SequencePattern:result.Pattern, DateCreated:time.Now(),
		CumulativeMatchCount:int64(result.ExampleCount), OriginalMatchCount:int64(result.ExampleCount), DateLastMatched:time.Now(), IgnorePattern:false, TagPositions:tp}
	err := p.Insert(ctx, tx, boil.Whitelist("id", "sequence_pattern", "date_created", "date_last_matched", "original_match_count", "cumulative_match_count", "ignore_pattern", "tag_positions"))
	if err != nil{
		logger.DatabaseInsertFailed("pattern", result.PatternId, err.Error())
		return false
	}

	//add the patternid and serviceid to the table
	for _, s := range result.Services{
		p.AddServiceIdServices(ctx, tx, false, s)
	}
	for _, e := range result.Examples{
		insertExample(ctx,tx,e,result.PatternId)
	}
	return true
}

func UpdatePattern(ctx context.Context, tx *sql.Tx, result AnalyzerResult){
	p, _ := models.FindPattern(ctx, tx, result.PatternId)
	p.DateLastMatched = time.Now()
	p.CumulativeMatchCount += int64(result.ExampleCount)
	_, err := p.Update(ctx, tx, boil.Infer())
	if err != nil{
		logger.DatabaseUpdateFailed("pattern", result.PatternId, err.Error())
	}
	//add the patternid and serviceid to the table
	for _, s := range result.Services{
		p.AddServiceIdServices(ctx, tx, false, s)
	}

	//if the example count is less than three, add the extra ones if different
	ct, _ := p.PatternExamples().Count(ctx, tx)
	if ct < 3 {
		ex, _ := p.PatternExamples().All(ctx, tx)
		for _, e := range result.Examples{
			found := false
			for _, h := range ex{
				if h.ExampleDetail == e.Message{
					found = true
					break
				}
			}
			if !found{
				insertExample(ctx,tx,e,result.PatternId)
			}
		}
	}
}

func insertExample(ctx context.Context, tx *sql.Tx, lr LogRecord, pid string){
	id, err := uuid.NewV4()
	if err !=nil {
		logger.DatabaseInsertFailed("example", pid, err.Error())
	}
	ex := models.Example{ExampleDetail:strings.TrimRight(lr.Message, " "), PatternID:pid, ID:id.String(), ServiceID:GenerateIDFromString(lr.Service)}
	err = ex.Insert(ctx, tx, boil.Infer())
	if err != nil{
		logger.DatabaseInsertFailed("example", pid, err.Error())
	}
}

func SaveExistingToDatabase(rmap map[string]AnalyzerResult) {
	db, ctx := OpenDbandSetContext()
	defer db.Close()
	//exisitng services
	smap := GetServicesFromDatabase(db, ctx)
	//services to be added to db
	nmap := make(map[string]string)
	//add the patterns and examples
	for _, result := range rmap {
		for _, s := range result.Services{
			//check the services if it exists and if not append.
			_, ok := smap[s.ID]
			if !ok{
				nmap[s.ID] = s.Name
			}
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		logger.HandleFatal("Could not start a transaction to save to the database.")
	}
	//start with the service, so not to cause a primary key violation
	for sid, m := range nmap{
		AddService(ctx, tx, sid, m)
	}
	tx.Commit()

	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		logger.HandleFatal("Could not start a transaction to save to the database.")
	}
	//here we want to update the existing patterns with count and last matched
	pmap := GetPatternsFromDatabase(db, ctx)
	for _, result := range rmap {
		_, found := pmap[result.PatternId]
		if found{
			UpdatePattern(ctx, tx, result)
		}
	}
	tx.Commit()

}

func SaveToDatabase(amap map[string]AnalyzerResult) (int, int) {
	var (
		new = 0
		saved = 0
	)
	db, ctx := OpenDbandSetContext()
	defer db.Close()
	//exisitng services
	smap := GetServicesFromDatabase(db, ctx)
	//services to be added to db
	nmap := make(map[string]string)
	//add the patterns and examples
	for _, result := range amap {
		for _, s := range result.Services{
			//check the services if it exists and if not append.
			_, ok := smap[s.ID]
			if !ok{
				nmap[s.ID] = s.Name
			}
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		logger.HandleFatal("Could not start a transaction to save to the database.")
	}
	//start with the service, so not to cause a primary key violation
	for sid, m := range nmap{
		AddService(ctx, tx, sid, m)
	}
	tx.Commit()

	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		logger.HandleFatal("Could not start a transaction to save to the database.")
	}

	tr := GetSaveThreshold()
	//technically we should not have any existing patterns passed to here, but just in case
	//lets check first
	pmap := GetPatternsFromDatabase(db, ctx)
	for _, result := range amap {
		_, found := pmap[result.PatternId]
		if !found{
			if AddPattern(ctx, tx, result, tr){
				saved++
			}
			new++
		}else{
			UpdatePattern(ctx, tx, result)
		}
	}
	tx.Commit()

	return new, saved
}