// Code generated by SQLBoiler (https://github.com/volatiletech/sqlboiler). DO NOT EDIT.
// This file is meant to be re-generated in place and/or deleted at any time.

package models

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/volatiletech/sqlboiler/boil"
	"github.com/volatiletech/sqlboiler/queries"
	"github.com/volatiletech/sqlboiler/queries/qm"
	"github.com/volatiletech/sqlboiler/queries/qmhelper"
	"github.com/volatiletech/sqlboiler/strmangle"
)

// Service is an object representing the database table.
type Service struct {
	ID          string    `boil:"id" json:"id" toml:"id" yaml:"id"`
	Name        string    `boil:"name" json:"name" toml:"name" yaml:"name"`
	DateCreated time.Time `boil:"date_created" json:"date_created" toml:"date_created" yaml:"date_created"`

	R *serviceR `boil:"-" json:"-" toml:"-" yaml:"-"`
	L serviceL  `boil:"-" json:"-" toml:"-" yaml:"-"`
}

var ServiceColumns = struct {
	ID          string
	Name        string
	DateCreated string
}{
	ID:          "id",
	Name:        "name",
	DateCreated: "date_created",
}

// Generated where

var ServiceWhere = struct {
	ID          whereHelperstring
	Name        whereHelperstring
	DateCreated whereHelpertime_Time
}{
	ID:          whereHelperstring{field: `id`},
	Name:        whereHelperstring{field: `name`},
	DateCreated: whereHelpertime_Time{field: `date_created`},
}

// ServiceRels is where relationship names are stored.
var ServiceRels = struct {
	ServiceExamples   string
	PatternIdPatterns string
}{
	ServiceExamples:   "ServiceExamples",
	PatternIdPatterns: "PatternIdPatterns",
}

// serviceR is where relationships are stored.
type serviceR struct {
	ServiceExamples   ExampleSlice
	PatternIdPatterns PatternSlice
}

// NewStruct creates a new relationship struct
func (*serviceR) NewStruct() *serviceR {
	return &serviceR{}
}

// serviceL is where Load methods for each relationship are stored.
type serviceL struct{}

var (
	serviceColumns               = []string{"id", "name", "date_created"}
	serviceColumnsWithoutDefault = []string{"id", "name", "date_created"}
	serviceColumnsWithDefault    = []string{}
	servicePrimaryKeyColumns     = []string{"id"}
)

type (
	// ServiceSlice is an alias for a slice of pointers to Service.
	// This should generally be used opposed to []Service.
	ServiceSlice []*Service
	// ServiceHook is the signature for custom Service hook methods
	ServiceHook func(context.Context, boil.ContextExecutor, *Service) error

	serviceQuery struct {
		*queries.Query
	}
)

// Cache for insert, update and upsert
var (
	serviceType                 = reflect.TypeOf(&Service{})
	serviceMapping              = queries.MakeStructMapping(serviceType)
	servicePrimaryKeyMapping, _ = queries.BindMapping(serviceType, serviceMapping, servicePrimaryKeyColumns)
	serviceInsertCacheMut       sync.RWMutex
	serviceInsertCache          = make(map[string]insertCache)
	serviceUpdateCacheMut       sync.RWMutex
	serviceUpdateCache          = make(map[string]updateCache)
	serviceUpsertCacheMut       sync.RWMutex
	serviceUpsertCache          = make(map[string]insertCache)
)

var (
	// Force time package dependency for automated UpdatedAt/CreatedAt.
	_ = time.Second
	// Force qmhelper dependency for where clause generation (which doesn't
	// always happen)
	_ = qmhelper.Where
)

var serviceBeforeInsertHooks []ServiceHook
var serviceBeforeUpdateHooks []ServiceHook
var serviceBeforeDeleteHooks []ServiceHook
var serviceBeforeUpsertHooks []ServiceHook

var serviceAfterInsertHooks []ServiceHook
var serviceAfterSelectHooks []ServiceHook
var serviceAfterUpdateHooks []ServiceHook
var serviceAfterDeleteHooks []ServiceHook
var serviceAfterUpsertHooks []ServiceHook

// doBeforeInsertHooks executes all "before insert" hooks.
func (o *Service) doBeforeInsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range serviceBeforeInsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeUpdateHooks executes all "before Update" hooks.
func (o *Service) doBeforeUpdateHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range serviceBeforeUpdateHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeDeleteHooks executes all "before Delete" hooks.
func (o *Service) doBeforeDeleteHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range serviceBeforeDeleteHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeUpsertHooks executes all "before Upsert" hooks.
func (o *Service) doBeforeUpsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range serviceBeforeUpsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterInsertHooks executes all "after Insert" hooks.
func (o *Service) doAfterInsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range serviceAfterInsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterSelectHooks executes all "after Select" hooks.
func (o *Service) doAfterSelectHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range serviceAfterSelectHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterUpdateHooks executes all "after Update" hooks.
func (o *Service) doAfterUpdateHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range serviceAfterUpdateHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterDeleteHooks executes all "after Delete" hooks.
func (o *Service) doAfterDeleteHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range serviceAfterDeleteHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterUpsertHooks executes all "after Upsert" hooks.
func (o *Service) doAfterUpsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range serviceAfterUpsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// AddServiceHook registers your hook function for all future operations.
func AddServiceHook(hookPoint boil.HookPoint, serviceHook ServiceHook) {
	switch hookPoint {
	case boil.BeforeInsertHook:
		serviceBeforeInsertHooks = append(serviceBeforeInsertHooks, serviceHook)
	case boil.BeforeUpdateHook:
		serviceBeforeUpdateHooks = append(serviceBeforeUpdateHooks, serviceHook)
	case boil.BeforeDeleteHook:
		serviceBeforeDeleteHooks = append(serviceBeforeDeleteHooks, serviceHook)
	case boil.BeforeUpsertHook:
		serviceBeforeUpsertHooks = append(serviceBeforeUpsertHooks, serviceHook)
	case boil.AfterInsertHook:
		serviceAfterInsertHooks = append(serviceAfterInsertHooks, serviceHook)
	case boil.AfterSelectHook:
		serviceAfterSelectHooks = append(serviceAfterSelectHooks, serviceHook)
	case boil.AfterUpdateHook:
		serviceAfterUpdateHooks = append(serviceAfterUpdateHooks, serviceHook)
	case boil.AfterDeleteHook:
		serviceAfterDeleteHooks = append(serviceAfterDeleteHooks, serviceHook)
	case boil.AfterUpsertHook:
		serviceAfterUpsertHooks = append(serviceAfterUpsertHooks, serviceHook)
	}
}

// One returns a single service record from the query.
func (q serviceQuery) One(ctx context.Context, exec boil.ContextExecutor) (*Service, error) {
	o := &Service{}

	queries.SetLimit(q.Query, 1)

	err := q.Bind(ctx, exec, o)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, errors.Wrap(err, "models: failed to execute a one query for Services")
	}

	if err := o.doAfterSelectHooks(ctx, exec); err != nil {
		return o, err
	}

	return o, nil
}

// All returns all Service records from the query.
func (q serviceQuery) All(ctx context.Context, exec boil.ContextExecutor) (ServiceSlice, error) {
	var o []*Service

	err := q.Bind(ctx, exec, &o)
	if err != nil {
		return nil, errors.Wrap(err, "models: failed to assign all query results to Service slice")
	}

	if len(serviceAfterSelectHooks) != 0 {
		for _, obj := range o {
			if err := obj.doAfterSelectHooks(ctx, exec); err != nil {
				return o, err
			}
		}
	}

	return o, nil
}

// Count returns the count of all Service records in the query.
func (q serviceQuery) Count(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	var count int64

	queries.SetSelect(q.Query, nil)
	queries.SetCount(q.Query)

	err := q.Query.QueryRowContext(ctx, exec).Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to count Services rows")
	}

	return count, nil
}

// Exists checks if the row exists in the table.
func (q serviceQuery) Exists(ctx context.Context, exec boil.ContextExecutor) (bool, error) {
	var count int64

	queries.SetSelect(q.Query, nil)
	queries.SetCount(q.Query)
	queries.SetLimit(q.Query, 1)

	err := q.Query.QueryRowContext(ctx, exec).Scan(&count)
	if err != nil {
		return false, errors.Wrap(err, "models: failed to check if Services exists")
	}

	return count > 0, nil
}

// ServiceExamples retrieves all the Example's Examples with an executor via service_id column.
func (o *Service) ServiceExamples(mods ...qm.QueryMod) exampleQuery {
	var queryMods []qm.QueryMod
	if len(mods) != 0 {
		queryMods = append(queryMods, mods...)
	}

	queryMods = append(queryMods,
		qm.Where("\"Examples\".\"service_id\"=?", o.ID),
	)

	query := Examples(queryMods...)
	queries.SetFrom(query.Query, "\"Examples\"")

	if len(queries.GetSelect(query.Query)) == 0 {
		queries.SetSelect(query.Query, []string{"\"Examples\".*"})
	}

	return query
}

// PatternIdPatterns retrieves all the Pattern's Patterns with an executor via id column.
func (o *Service) PatternIdPatterns(mods ...qm.QueryMod) patternQuery {
	var queryMods []qm.QueryMod
	if len(mods) != 0 {
		queryMods = append(queryMods, mods...)
	}

	queryMods = append(queryMods,
		qm.InnerJoin("\"PatternsServices\" on \"Patterns\".\"id\" = \"PatternsServices\".\"PatternId\""),
		qm.Where("\"PatternsServices\".\"ServiceId\"=?", o.ID),
	)

	query := Patterns(queryMods...)
	queries.SetFrom(query.Query, "\"Patterns\"")

	if len(queries.GetSelect(query.Query)) == 0 {
		queries.SetSelect(query.Query, []string{"\"Patterns\".*"})
	}

	return query
}

// LoadServiceExamples allows an eager lookup of values, cached into the
// loaded structs of the objects. This is for a 1-M or N-M relationship.
func (serviceL) LoadServiceExamples(ctx context.Context, e boil.ContextExecutor, singular bool, maybeService interface{}, mods queries.Applicator) error {
	var slice []*Service
	var object *Service

	if singular {
		object = maybeService.(*Service)
	} else {
		slice = *maybeService.(*[]*Service)
	}

	args := make([]interface{}, 0, 1)
	if singular {
		if object.R == nil {
			object.R = &serviceR{}
		}
		args = append(args, object.ID)
	} else {
	Outer:
		for _, obj := range slice {
			if obj.R == nil {
				obj.R = &serviceR{}
			}

			for _, a := range args {
				if a == obj.ID {
					continue Outer
				}
			}

			args = append(args, obj.ID)
		}
	}

	if len(args) == 0 {
		return nil
	}

	query := NewQuery(qm.From(`Examples`), qm.WhereIn(`service_id in ?`, args...))
	if mods != nil {
		mods.Apply(query)
	}

	results, err := query.QueryContext(ctx, e)
	if err != nil {
		return errors.Wrap(err, "failed to eager load Examples")
	}

	var resultSlice []*Example
	if err = queries.Bind(results, &resultSlice); err != nil {
		return errors.Wrap(err, "failed to bind eager loaded slice Examples")
	}

	if err = results.Close(); err != nil {
		return errors.Wrap(err, "failed to close results in eager load on Examples")
	}
	if err = results.Err(); err != nil {
		return errors.Wrap(err, "error occurred during iteration of eager loaded relations for Examples")
	}

	if len(exampleAfterSelectHooks) != 0 {
		for _, obj := range resultSlice {
			if err := obj.doAfterSelectHooks(ctx, e); err != nil {
				return err
			}
		}
	}
	if singular {
		object.R.ServiceExamples = resultSlice
		for _, foreign := range resultSlice {
			if foreign.R == nil {
				foreign.R = &exampleR{}
			}
			foreign.R.Service = object
		}
		return nil
	}

	for _, foreign := range resultSlice {
		for _, local := range slice {
			if local.ID == foreign.ServiceID {
				local.R.ServiceExamples = append(local.R.ServiceExamples, foreign)
				if foreign.R == nil {
					foreign.R = &exampleR{}
				}
				foreign.R.Service = local
				break
			}
		}
	}

	return nil
}

// LoadPatternIdPatterns allows an eager lookup of values, cached into the
// loaded structs of the objects. This is for a 1-M or N-M relationship.
func (serviceL) LoadPatternIdPatterns(ctx context.Context, e boil.ContextExecutor, singular bool, maybeService interface{}, mods queries.Applicator) error {
	var slice []*Service
	var object *Service

	if singular {
		object = maybeService.(*Service)
	} else {
		slice = *maybeService.(*[]*Service)
	}

	args := make([]interface{}, 0, 1)
	if singular {
		if object.R == nil {
			object.R = &serviceR{}
		}
		args = append(args, object.ID)
	} else {
	Outer:
		for _, obj := range slice {
			if obj.R == nil {
				obj.R = &serviceR{}
			}

			for _, a := range args {
				if a == obj.ID {
					continue Outer
				}
			}

			args = append(args, obj.ID)
		}
	}

	if len(args) == 0 {
		return nil
	}

	query := NewQuery(
		qm.Select("\"Patterns\".*, \"a\".\"ServiceId\""),
		qm.From("\"Patterns\""),
		qm.InnerJoin("\"PatternsServices\" as \"a\" on \"Patterns\".\"id\" = \"a\".\"PatternId\""),
		qm.WhereIn("\"a\".\"ServiceId\" in ?", args...),
	)
	if mods != nil {
		mods.Apply(query)
	}

	results, err := query.QueryContext(ctx, e)
	if err != nil {
		return errors.Wrap(err, "failed to eager load Patterns")
	}

	var resultSlice []*Pattern

	var localJoinCols []string
	for results.Next() {
		one := new(Pattern)
		var localJoinCol string

		err = results.Scan(&one.ID, &one.SequencePattern, &one.TagPositions, &one.DateCreated, &one.DateLastMatched, &one.OriginalMatchCount, &one.CumulativeMatchCount, &one.IgnorePattern, &localJoinCol)
		if err != nil {
			return errors.Wrap(err, "failed to scan eager loaded results for Patterns")
		}
		if err = results.Err(); err != nil {
			return errors.Wrap(err, "failed to plebian-bind eager loaded slice Patterns")
		}

		resultSlice = append(resultSlice, one)
		localJoinCols = append(localJoinCols, localJoinCol)
	}

	if err = results.Close(); err != nil {
		return errors.Wrap(err, "failed to close results in eager load on Patterns")
	}
	if err = results.Err(); err != nil {
		return errors.Wrap(err, "error occurred during iteration of eager loaded relations for Patterns")
	}

	if len(patternAfterSelectHooks) != 0 {
		for _, obj := range resultSlice {
			if err := obj.doAfterSelectHooks(ctx, e); err != nil {
				return err
			}
		}
	}
	if singular {
		object.R.PatternIdPatterns = resultSlice
		for _, foreign := range resultSlice {
			if foreign.R == nil {
				foreign.R = &patternR{}
			}
			foreign.R.ServiceIdServices = append(foreign.R.ServiceIdServices, object)
		}
		return nil
	}

	for i, foreign := range resultSlice {
		localJoinCol := localJoinCols[i]
		for _, local := range slice {
			if local.ID == localJoinCol {
				local.R.PatternIdPatterns = append(local.R.PatternIdPatterns, foreign)
				if foreign.R == nil {
					foreign.R = &patternR{}
				}
				foreign.R.ServiceIdServices = append(foreign.R.ServiceIdServices, local)
				break
			}
		}
	}

	return nil
}

// AddServiceExamples adds the given related objects to the existing relationships
// of the Service, optionally inserting them as new records.
// Appends related to o.R.ServiceExamples.
// Sets related.R.Service appropriately.
func (o *Service) AddServiceExamples(ctx context.Context, exec boil.ContextExecutor, insert bool, related ...*Example) error {
	var err error
	for _, rel := range related {
		if insert {
			rel.ServiceID = o.ID
			if err = rel.Insert(ctx, exec, boil.Infer()); err != nil {
				return errors.Wrap(err, "failed to insert into foreign table")
			}
		} else {
			updateQuery := fmt.Sprintf(
				"UPDATE \"Examples\" SET %s WHERE %s",
				strmangle.SetParamNames("\"", "\"", 0, []string{"service_id"}),
				strmangle.WhereClause("\"", "\"", 0, examplePrimaryKeyColumns),
			)
			values := []interface{}{o.ID, rel.ID}

			if boil.DebugMode {
				fmt.Fprintln(boil.DebugWriter, updateQuery)
				fmt.Fprintln(boil.DebugWriter, values)
			}

			if _, err = exec.ExecContext(ctx, updateQuery, values...); err != nil {
				return errors.Wrap(err, "failed to update foreign table")
			}

			rel.ServiceID = o.ID
		}
	}

	if o.R == nil {
		o.R = &serviceR{
			ServiceExamples: related,
		}
	} else {
		o.R.ServiceExamples = append(o.R.ServiceExamples, related...)
	}

	for _, rel := range related {
		if rel.R == nil {
			rel.R = &exampleR{
				Service: o,
			}
		} else {
			rel.R.Service = o
		}
	}
	return nil
}

// AddPatternIdPatterns adds the given related objects to the existing relationships
// of the Service, optionally inserting them as new records.
// Appends related to o.R.PatternIdPatterns.
// Sets related.R.ServiceIdServices appropriately.
func (o *Service) AddPatternIdPatterns(ctx context.Context, exec boil.ContextExecutor, insert bool, related ...*Pattern) error {
	var err error
	for _, rel := range related {
		if insert {
			if err = rel.Insert(ctx, exec, boil.Infer()); err != nil {
				return errors.Wrap(err, "failed to insert into foreign table")
			}
		}
	}

	for _, rel := range related {
		query := "insert into \"PatternsServices\" (\"ServiceId\", \"PatternId\") values (?, ?)"
		values := []interface{}{o.ID, rel.ID}

		if boil.DebugMode {
			fmt.Fprintln(boil.DebugWriter, query)
			fmt.Fprintln(boil.DebugWriter, values)
		}

		_, err = exec.ExecContext(ctx, query, values...)
		if err != nil {
			return errors.Wrap(err, "failed to insert into join table")
		}
	}
	if o.R == nil {
		o.R = &serviceR{
			PatternIdPatterns: related,
		}
	} else {
		o.R.PatternIdPatterns = append(o.R.PatternIdPatterns, related...)
	}

	for _, rel := range related {
		if rel.R == nil {
			rel.R = &patternR{
				ServiceIdServices: ServiceSlice{o},
			}
		} else {
			rel.R.ServiceIdServices = append(rel.R.ServiceIdServices, o)
		}
	}
	return nil
}

// SetPatternIdPatterns removes all previously related items of the
// Service replacing them completely with the passed
// in related items, optionally inserting them as new records.
// Sets o.R.ServiceIdServices's PatternIdPatterns accordingly.
// Replaces o.R.PatternIdPatterns with related.
// Sets related.R.ServiceIdServices's PatternIdPatterns accordingly.
func (o *Service) SetPatternIdPatterns(ctx context.Context, exec boil.ContextExecutor, insert bool, related ...*Pattern) error {
	query := "delete from \"PatternsServices\" where \"ServiceId\" = ?"
	values := []interface{}{o.ID}
	if boil.DebugMode {
		fmt.Fprintln(boil.DebugWriter, query)
		fmt.Fprintln(boil.DebugWriter, values)
	}

	_, err := exec.ExecContext(ctx, query, values...)
	if err != nil {
		return errors.Wrap(err, "failed to remove relationships before set")
	}

	removePatternIdPatternsFromServiceIdServicesSlice(o, related)
	if o.R != nil {
		o.R.PatternIdPatterns = nil
	}
	return o.AddPatternIdPatterns(ctx, exec, insert, related...)
}

// RemovePatternIdPatterns relationships from objects passed in.
// Removes related items from R.PatternIdPatterns (uses pointer comparison, removal does not keep order)
// Sets related.R.ServiceIdServices.
func (o *Service) RemovePatternIdPatterns(ctx context.Context, exec boil.ContextExecutor, related ...*Pattern) error {
	var err error
	query := fmt.Sprintf(
		"delete from \"PatternsServices\" where \"ServiceId\" = ? and \"PatternId\" in (%s)",
		strmangle.Placeholders(dialect.UseIndexPlaceholders, len(related), 2, 1),
	)
	values := []interface{}{o.ID}
	for _, rel := range related {
		values = append(values, rel.ID)
	}

	if boil.DebugMode {
		fmt.Fprintln(boil.DebugWriter, query)
		fmt.Fprintln(boil.DebugWriter, values)
	}

	_, err = exec.ExecContext(ctx, query, values...)
	if err != nil {
		return errors.Wrap(err, "failed to remove relationships before set")
	}
	removePatternIdPatternsFromServiceIdServicesSlice(o, related)
	if o.R == nil {
		return nil
	}

	for _, rel := range related {
		for i, ri := range o.R.PatternIdPatterns {
			if rel != ri {
				continue
			}

			ln := len(o.R.PatternIdPatterns)
			if ln > 1 && i < ln-1 {
				o.R.PatternIdPatterns[i] = o.R.PatternIdPatterns[ln-1]
			}
			o.R.PatternIdPatterns = o.R.PatternIdPatterns[:ln-1]
			break
		}
	}

	return nil
}

func removePatternIdPatternsFromServiceIdServicesSlice(o *Service, related []*Pattern) {
	for _, rel := range related {
		if rel.R == nil {
			continue
		}
		for i, ri := range rel.R.ServiceIdServices {
			if o.ID != ri.ID {
				continue
			}

			ln := len(rel.R.ServiceIdServices)
			if ln > 1 && i < ln-1 {
				rel.R.ServiceIdServices[i] = rel.R.ServiceIdServices[ln-1]
			}
			rel.R.ServiceIdServices = rel.R.ServiceIdServices[:ln-1]
			break
		}
	}
}

// Services retrieves all the records using an executor.
func Services(mods ...qm.QueryMod) serviceQuery {
	mods = append(mods, qm.From("\"Services\""))
	return serviceQuery{NewQuery(mods...)}
}

// FindService retrieves a single record by ID with an executor.
// If selectCols is empty Find will return all columns.
func FindService(ctx context.Context, exec boil.ContextExecutor, iD string, selectCols ...string) (*Service, error) {
	serviceObj := &Service{}

	sel := "*"
	if len(selectCols) > 0 {
		sel = strings.Join(strmangle.IdentQuoteSlice(dialect.LQ, dialect.RQ, selectCols), ",")
	}
	query := fmt.Sprintf(
		"select %s from \"Services\" where \"id\"=?", sel,
	)

	q := queries.Raw(query, iD)

	err := q.Bind(ctx, exec, serviceObj)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, errors.Wrap(err, "models: unable to select from Services")
	}

	return serviceObj, nil
}

// Insert a single record using an executor.
// See boil.Columns.InsertColumnSet documentation to understand column list inference for inserts.
func (o *Service) Insert(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) error {
	if o == nil {
		return errors.New("models: no Services provided for insertion")
	}

	var err error

	if err := o.doBeforeInsertHooks(ctx, exec); err != nil {
		return err
	}

	nzDefaults := queries.NonZeroDefaultSet(serviceColumnsWithDefault, o)

	key := makeCacheKey(columns, nzDefaults)
	serviceInsertCacheMut.RLock()
	cache, cached := serviceInsertCache[key]
	serviceInsertCacheMut.RUnlock()

	if !cached {
		wl, returnColumns := columns.InsertColumnSet(
			serviceColumns,
			serviceColumnsWithDefault,
			serviceColumnsWithoutDefault,
			nzDefaults,
		)

		cache.valueMapping, err = queries.BindMapping(serviceType, serviceMapping, wl)
		if err != nil {
			return err
		}
		cache.retMapping, err = queries.BindMapping(serviceType, serviceMapping, returnColumns)
		if err != nil {
			return err
		}
		if len(wl) != 0 {
			cache.query = fmt.Sprintf("INSERT INTO \"Services\" (\"%s\") %%sVALUES (%s)%%s", strings.Join(wl, "\",\""), strmangle.Placeholders(dialect.UseIndexPlaceholders, len(wl), 1, 1))
		} else {
			cache.query = "INSERT INTO \"Services\" () VALUES ()%s%s"
		}

		var queryOutput, queryReturning string

		if len(cache.retMapping) != 0 {
			cache.retQuery = fmt.Sprintf("SELECT \"%s\" FROM \"Services\" WHERE %s", strings.Join(returnColumns, "\",\""), strmangle.WhereClause("\"", "\"", 0, servicePrimaryKeyColumns))
		}

		cache.query = fmt.Sprintf(cache.query, queryOutput, queryReturning)
	}

	value := reflect.Indirect(reflect.ValueOf(o))
	vals := queries.ValuesFromMapping(value, cache.valueMapping)

	if boil.DebugMode {
		fmt.Fprintln(boil.DebugWriter, cache.query)
		fmt.Fprintln(boil.DebugWriter, vals)
	}

	_, err = exec.ExecContext(ctx, cache.query, vals...)

	if err != nil {
		return errors.Wrap(err, "models: unable to insert into Services")
	}

	var identifierCols []interface{}

	if len(cache.retMapping) == 0 {
		goto CacheNoHooks
	}

	identifierCols = []interface{}{
		o.ID,
	}

	if boil.DebugMode {
		fmt.Fprintln(boil.DebugWriter, cache.retQuery)
		fmt.Fprintln(boil.DebugWriter, identifierCols...)
	}

	err = exec.QueryRowContext(ctx, cache.retQuery, identifierCols...).Scan(queries.PtrsFromMapping(value, cache.retMapping)...)
	if err != nil {
		return errors.Wrap(err, "models: unable to populate default values for Services")
	}

CacheNoHooks:
	if !cached {
		serviceInsertCacheMut.Lock()
		serviceInsertCache[key] = cache
		serviceInsertCacheMut.Unlock()
	}

	return o.doAfterInsertHooks(ctx, exec)
}

// Update uses an executor to update the Service.
// See boil.Columns.UpdateColumnSet documentation to understand column list inference for updates.
// Update does not automatically update the record in case of default values. Use .Reload() to refresh the records.
func (o *Service) Update(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) (int64, error) {
	var err error
	if err = o.doBeforeUpdateHooks(ctx, exec); err != nil {
		return 0, err
	}
	key := makeCacheKey(columns, nil)
	serviceUpdateCacheMut.RLock()
	cache, cached := serviceUpdateCache[key]
	serviceUpdateCacheMut.RUnlock()

	if !cached {
		wl := columns.UpdateColumnSet(
			serviceColumns,
			servicePrimaryKeyColumns,
		)

		if !columns.IsWhitelist() {
			wl = strmangle.SetComplement(wl, []string{"created_at"})
		}
		if len(wl) == 0 {
			return 0, errors.New("models: unable to update Services, could not build whitelist")
		}

		cache.query = fmt.Sprintf("UPDATE \"Services\" SET %s WHERE %s",
			strmangle.SetParamNames("\"", "\"", 0, wl),
			strmangle.WhereClause("\"", "\"", 0, servicePrimaryKeyColumns),
		)
		cache.valueMapping, err = queries.BindMapping(serviceType, serviceMapping, append(wl, servicePrimaryKeyColumns...))
		if err != nil {
			return 0, err
		}
	}

	values := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(o)), cache.valueMapping)

	if boil.DebugMode {
		fmt.Fprintln(boil.DebugWriter, cache.query)
		fmt.Fprintln(boil.DebugWriter, values)
	}

	var result sql.Result
	result, err = exec.ExecContext(ctx, cache.query, values...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update Services row")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by update for Services")
	}

	if !cached {
		serviceUpdateCacheMut.Lock()
		serviceUpdateCache[key] = cache
		serviceUpdateCacheMut.Unlock()
	}

	return rowsAff, o.doAfterUpdateHooks(ctx, exec)
}

// UpdateAll updates all rows with the specified column values.
func (q serviceQuery) UpdateAll(ctx context.Context, exec boil.ContextExecutor, cols M) (int64, error) {
	queries.SetUpdate(q.Query, cols)

	result, err := q.Query.ExecContext(ctx, exec)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update all for Services")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to retrieve rows affected for Services")
	}

	return rowsAff, nil
}

// UpdateAll updates all rows with the specified column values, using an executor.
func (o ServiceSlice) UpdateAll(ctx context.Context, exec boil.ContextExecutor, cols M) (int64, error) {
	ln := int64(len(o))
	if ln == 0 {
		return 0, nil
	}

	if len(cols) == 0 {
		return 0, errors.New("models: update all requires at least one column argument")
	}

	colNames := make([]string, len(cols))
	args := make([]interface{}, len(cols))

	i := 0
	for name, value := range cols {
		colNames[i] = name
		args[i] = value
		i++
	}

	// Append all of the primary key values for each column
	for _, obj := range o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), servicePrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := fmt.Sprintf("UPDATE \"Services\" SET %s WHERE %s",
		strmangle.SetParamNames("\"", "\"", 0, colNames),
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, servicePrimaryKeyColumns, len(o)))

	if boil.DebugMode {
		fmt.Fprintln(boil.DebugWriter, sql)
		fmt.Fprintln(boil.DebugWriter, args...)
	}

	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update all in service slice")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to retrieve rows affected all in update all service")
	}
	return rowsAff, nil
}

// Delete deletes a single Service record with an executor.
// Delete will match against the primary key column to find the record to delete.
func (o *Service) Delete(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if o == nil {
		return 0, errors.New("models: no Service provided for delete")
	}

	if err := o.doBeforeDeleteHooks(ctx, exec); err != nil {
		return 0, err
	}

	args := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(o)), servicePrimaryKeyMapping)
	sql := "DELETE FROM \"Services\" WHERE \"id\"=?"

	if boil.DebugMode {
		fmt.Fprintln(boil.DebugWriter, sql)
		fmt.Fprintln(boil.DebugWriter, args...)
	}

	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete from Services")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by delete for Services")
	}

	if err := o.doAfterDeleteHooks(ctx, exec); err != nil {
		return 0, err
	}

	return rowsAff, nil
}

// DeleteAll deletes all matching rows.
func (q serviceQuery) DeleteAll(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if q.Query == nil {
		return 0, errors.New("models: no serviceQuery provided for delete all")
	}

	queries.SetDelete(q.Query)

	result, err := q.Query.ExecContext(ctx, exec)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete all from Services")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by deleteall for Services")
	}

	return rowsAff, nil
}

// DeleteAll deletes all rows in the slice, using an executor.
func (o ServiceSlice) DeleteAll(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if o == nil {
		return 0, errors.New("models: no Service slice provided for delete all")
	}

	if len(o) == 0 {
		return 0, nil
	}

	if len(serviceBeforeDeleteHooks) != 0 {
		for _, obj := range o {
			if err := obj.doBeforeDeleteHooks(ctx, exec); err != nil {
				return 0, err
			}
		}
	}

	var args []interface{}
	for _, obj := range o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), servicePrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := "DELETE FROM \"Services\" WHERE " +
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, servicePrimaryKeyColumns, len(o))

	if boil.DebugMode {
		fmt.Fprintln(boil.DebugWriter, sql)
		fmt.Fprintln(boil.DebugWriter, args)
	}

	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete all from service slice")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by deleteall for Services")
	}

	if len(serviceAfterDeleteHooks) != 0 {
		for _, obj := range o {
			if err := obj.doAfterDeleteHooks(ctx, exec); err != nil {
				return 0, err
			}
		}
	}

	return rowsAff, nil
}

// Reload refetches the object from the database
// using the primary keys with an executor.
func (o *Service) Reload(ctx context.Context, exec boil.ContextExecutor) error {
	ret, err := FindService(ctx, exec, o.ID)
	if err != nil {
		return err
	}

	*o = *ret
	return nil
}

// ReloadAll refetches every row with matching primary key column values
// and overwrites the original object slice with the newly updated slice.
func (o *ServiceSlice) ReloadAll(ctx context.Context, exec boil.ContextExecutor) error {
	if o == nil || len(*o) == 0 {
		return nil
	}

	slice := ServiceSlice{}
	var args []interface{}
	for _, obj := range *o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), servicePrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := "SELECT \"Services\".* FROM \"Services\" WHERE " +
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 0, servicePrimaryKeyColumns, len(*o))

	q := queries.Raw(sql, args...)

	err := q.Bind(ctx, exec, &slice)
	if err != nil {
		return errors.Wrap(err, "models: unable to reload all in ServiceSlice")
	}

	*o = slice

	return nil
}

// ServiceExists checks if the Service row exists.
func ServiceExists(ctx context.Context, exec boil.ContextExecutor, iD string) (bool, error) {
	var exists bool
	sql := "select exists(select 1 from \"Services\" where \"id\"=? limit 1)"

	if boil.DebugMode {
		fmt.Fprintln(boil.DebugWriter, sql)
		fmt.Fprintln(boil.DebugWriter, iD)
	}

	row := exec.QueryRowContext(ctx, sql, iD)

	err := row.Scan(&exists)
	if err != nil {
		return false, errors.Wrap(err, "models: unable to check if Services exists")
	}

	return exists, nil
}
