package e2e_clickhouse

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PeerDB-io/peer-flow/e2e"
	"github.com/PeerDB-io/peer-flow/e2eshared"
	"github.com/PeerDB-io/peer-flow/generated/protos"
	"github.com/PeerDB-io/peer-flow/model"
	"github.com/PeerDB-io/peer-flow/shared"
	peerflow "github.com/PeerDB-io/peer-flow/workflows"
)

func TestPeerFlowE2ETestSuiteCH(t *testing.T) {
	e2eshared.RunSuite(t, SetupSuite)
}

func (s ClickHouseSuite) attachSchemaSuffix(tableName string) string {
	return fmt.Sprintf("e2e_test_%s.%s", s.suffix, tableName)
}

func (s ClickHouseSuite) attachSuffix(input string) string {
	return fmt.Sprintf("%s_%s", input, s.suffix)
}

func (s ClickHouseSuite) Test_Addition_Removal() {
	tc := e2e.NewTemporalClient(s.t)

	srcTableName := s.attachSchemaSuffix("test_table_add_remove")
	addedSrcTableName := s.attachSchemaSuffix("test_table_add_remove_added")
	dstTableName := "test_table_add_remove_target"
	addedDstTableName := "test_table_add_remove_target_added"

	_, err := s.Conn().Exec(context.Background(), fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id SERIAL PRIMARY KEY,
			key TEXT NOT NULL
		);
	`, srcTableName))
	require.NoError(s.t, err)

	_, err = s.Conn().Exec(context.Background(), fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s (
		id SERIAL PRIMARY KEY,
		key TEXT NOT NULL
	);
	`, addedSrcTableName))
	require.NoError(s.t, err)

	connectionGen := e2e.FlowConnectionGenerationConfig{
		FlowJobName:      s.attachSuffix("clickhousetableremoval"),
		TableNameMapping: map[string]string{srcTableName: dstTableName},
		Destination:      s.Peer().Name,
	}

	flowConnConfig := connectionGen.GenerateFlowConnectionConfigs(s.t)
	flowConnConfig.MaxBatchSize = 1

	env := e2e.ExecutePeerflow(tc, peerflow.CDCFlowWorkflow, flowConnConfig, nil)

	getFlowStatus := func() protos.FlowStatus {
		var flowStatus protos.FlowStatus
		val, err := env.Query(shared.FlowStatusQuery)
		e2e.EnvNoError(s.t, env, err)
		err = val.Get(&flowStatus)
		e2e.EnvNoError(s.t, env, err)

		return flowStatus
	}

	e2e.SetupCDCFlowStatusQuery(s.t, env, flowConnConfig)
	_, err = s.Conn().Exec(context.Background(), fmt.Sprintf(`
		INSERT INTO %s (key) VALUES ('test');
	`, srcTableName))
	require.NoError(s.t, err)
	e2e.EnvWaitForEqualTablesWithNames(env, s, "first insert", "test_table_add_remove", dstTableName, "id,key")
	e2e.SignalWorkflow(env, model.FlowSignal, model.PauseSignal)
	e2e.EnvWaitFor(s.t, env, 4*time.Minute, "pausing for add table", func() bool {
		flowStatus := getFlowStatus()
		return flowStatus == protos.FlowStatus_STATUS_PAUSED
	})

	_, err = s.Conn().Exec(context.Background(),
		`SELECT pg_terminate_backend(pid) FROM pg_stat_activity
	 WHERE query LIKE '%START_REPLICATION%' AND query LIKE '%clickhousetableremoval%' AND backend_type='walsender'`)
	require.NoError(s.t, err)

	e2e.EnvWaitFor(s.t, env, 3*time.Minute, "waiting for replication to stop", func() bool {
		rows, err := s.Conn().Query(context.Background(), `
		SELECT pid FROM pg_stat_activity
		WHERE query LIKE '%START_REPLICATION%' AND query LIKE '%clickhousetableremoval%' AND backend_type='walsender'
		`)
		require.NoError(s.t, err)
		defer rows.Close()
		return !rows.Next()
	})

	e2e.SignalWorkflow(env, model.CDCDynamicPropertiesSignal, &protos.CDCFlowConfigUpdate{
		AdditionalTables: []*protos.TableMapping{
			{
				SourceTableIdentifier:      addedSrcTableName,
				DestinationTableIdentifier: addedDstTableName,
			},
		},
	})

	e2e.EnvWaitFor(s.t, env, 4*time.Minute, "adding table", func() bool {
		flowStatus := getFlowStatus()
		return flowStatus == protos.FlowStatus_STATUS_RUNNING
	})

	_, err = s.Conn().Exec(context.Background(), fmt.Sprintf(`
		INSERT INTO %s (key) VALUES ('test');
	`, addedSrcTableName))
	require.NoError(s.t, err)
	e2e.EnvWaitForEqualTablesWithNames(env, s, "first insert to added table", "test_table_add_remove_added", addedDstTableName, "id,key")
	e2e.SignalWorkflow(env, model.FlowSignal, model.PauseSignal)
	e2e.EnvWaitFor(s.t, env, 3*time.Minute, "pausing again for removing table", func() bool {
		flowStatus := getFlowStatus()
		return flowStatus == protos.FlowStatus_STATUS_PAUSED
	})

	_, err = s.Conn().Exec(context.Background(),
		`SELECT pg_terminate_backend(pid) FROM pg_stat_activity
	 WHERE query LIKE '%START_REPLICATION%' AND query LIKE '%clickhousetableremoval%' AND backend_type='walsender'`)
	require.NoError(s.t, err)

	e2e.EnvWaitFor(s.t, env, 3*time.Minute, "waiting for replication to stop", func() bool {
		rows, err := s.Conn().Query(context.Background(), `
		SELECT pid FROM pg_stat_activity
		WHERE query LIKE '%START_REPLICATION%' AND query LIKE '%clickhousetableremoval%' AND backend_type='walsender'
		`)
		require.NoError(s.t, err)
		defer rows.Close()
		return !rows.Next()
	})

	e2e.SignalWorkflow(env, model.CDCDynamicPropertiesSignal, &protos.CDCFlowConfigUpdate{
		RemovedTables: []*protos.TableMapping{
			{
				SourceTableIdentifier:      srcTableName,
				DestinationTableIdentifier: dstTableName,
			},
		},
	})

	e2e.EnvWaitFor(s.t, env, 4*time.Minute, "removing table", func() bool {
		flowStatus := getFlowStatus()
		return flowStatus == protos.FlowStatus_STATUS_RUNNING
	})

	_, err = s.Conn().Exec(context.Background(), fmt.Sprintf(`
	INSERT INTO %s (key) VALUES ('test');
	`, srcTableName))
	require.NoError(s.t, err)

	_, err = s.Conn().Exec(context.Background(), fmt.Sprintf(`
	INSERT INTO %s (key) VALUES ('test');
	`, addedSrcTableName))
	require.NoError(s.t, err)

	e2e.EnvWaitForEqualTablesWithNames(env, s, "second insert to added table", "test_table_add_remove_added", addedDstTableName, "id,key")

	rows, err := s.GetRows(dstTableName, "id")
	require.NoError(s.t, err)
	require.Len(s.t, rows.Records, 1, "expected no new rows in removed table")
	env.Cancel()
	e2e.RequireEnvCanceled(s.t, env)
}

func (s ClickHouseSuite) Test_Nullable() {
	srcTableName := "test_nullable"
	srcFullName := s.attachSchemaSuffix("test_nullable")
	dstTableName := "test_nullable_dst"

	_, err := s.Conn().Exec(context.Background(), fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id SERIAL PRIMARY KEY,
			key TEXT NOT NULL,
			val TEXT,
			n NUMERIC,
			t TIMESTAMP
		);
	`, srcFullName))
	require.NoError(s.t, err)

	_, err = s.Conn().Exec(context.Background(), fmt.Sprintf(`
	INSERT INTO %s (key) VALUES ('init');
	`, srcFullName))
	require.NoError(s.t, err)

	connectionGen := e2e.FlowConnectionGenerationConfig{
		FlowJobName:      s.attachSuffix("clickhouse_nullable"),
		TableNameMapping: map[string]string{srcFullName: dstTableName},
		Destination:      s.Peer().Name,
	}
	flowConnConfig := connectionGen.GenerateFlowConnectionConfigs(s.t)
	flowConnConfig.DoInitialSnapshot = true
	flowConnConfig.Env = map[string]string{"PEERDB_NULLABLE": "true"}

	tc := e2e.NewTemporalClient(s.t)
	env := e2e.ExecutePeerflow(tc, peerflow.CDCFlowWorkflow, flowConnConfig, nil)
	e2e.SetupCDCFlowStatusQuery(s.t, env, flowConnConfig)

	e2e.EnvWaitForEqualTablesWithNames(env, s, "waiting on initial", srcTableName, dstTableName, "id,key,val,n,t")

	_, err = s.Conn().Exec(context.Background(), fmt.Sprintf(`
	INSERT INTO %s (key) VALUES ('cdc');
	`, srcFullName))
	require.NoError(s.t, err)

	e2e.EnvWaitForEqualTablesWithNames(env, s, "waiting on cdc", srcTableName, dstTableName, "id,key,val,n,t")

	env.Cancel()
	e2e.RequireEnvCanceled(s.t, env)
}

func (s ClickHouseSuite) Test_Date32() {
	srcTableName := "test_date32"
	srcFullName := s.attachSchemaSuffix("test_date32")
	dstTableName := "test_date32_dst"

	_, err := s.Conn().Exec(context.Background(), fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id SERIAL PRIMARY KEY,
			key TEXT NOT NULL,
			d DATE NOT NULL
		);
	`, srcFullName))
	require.NoError(s.t, err)

	_, err = s.Conn().Exec(context.Background(), fmt.Sprintf(`
	INSERT INTO %s (key,d) VALUES ('init','1935-01-01');
	`, srcFullName))
	require.NoError(s.t, err)

	connectionGen := e2e.FlowConnectionGenerationConfig{
		FlowJobName:      s.attachSuffix("clickhouse_date32"),
		TableNameMapping: map[string]string{srcFullName: dstTableName},
		Destination:      s.Peer().Name,
	}
	flowConnConfig := connectionGen.GenerateFlowConnectionConfigs(s.t)
	flowConnConfig.DoInitialSnapshot = true

	tc := e2e.NewTemporalClient(s.t)
	env := e2e.ExecutePeerflow(tc, peerflow.CDCFlowWorkflow, flowConnConfig, nil)
	e2e.SetupCDCFlowStatusQuery(s.t, env, flowConnConfig)

	e2e.EnvWaitForEqualTablesWithNames(env, s, "waiting on initial", srcTableName, dstTableName, "id,key,d")

	_, err = s.Conn().Exec(context.Background(), fmt.Sprintf(`
	INSERT INTO %s (key,d) VALUES ('cdc','1935-01-01');
	`, srcFullName))
	require.NoError(s.t, err)

	e2e.EnvWaitForEqualTablesWithNames(env, s, "waiting on cdc", srcTableName, dstTableName, "id,key,d")

	env.Cancel()
	e2e.RequireEnvCanceled(s.t, env)
}

func (s ClickHouseSuite) Test_ColumnNamesWithSpaces() {
	srcTableName := "test_column_names_with_spaces"
	srcFullName := s.attachSchemaSuffix("test_column_names_with_spaces")
	dstTableName := "test_column_names_with_spaces_dst"

	_, err := s.Conn().Exec(context.Background(), fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			"id with space" SERIAL PRIMARY KEY,
			"column with space" TEXT NOT NULL,
			"another column with space" TEXT
		);
	`, srcFullName))
	require.NoError(s.t, err)

	_, err = s.Conn().Exec(context.Background(), fmt.Sprintf(`
	INSERT INTO %s ("column with space", "another column with space") VALUES ('init', 'value');
	`, srcFullName))
	require.NoError(s.t, err)

	connectionGen := e2e.FlowConnectionGenerationConfig{
		FlowJobName:      s.attachSuffix("clickhouse_column_names_with_spaces"),
		TableNameMapping: map[string]string{srcFullName: dstTableName},
		Destination:      s.Peer().Name,
	}
	flowConnConfig := connectionGen.GenerateFlowConnectionConfigs(s.t)
	flowConnConfig.DoInitialSnapshot = true

	tc := e2e.NewTemporalClient(s.t)
	env := e2e.ExecutePeerflow(tc, peerflow.CDCFlowWorkflow, flowConnConfig, nil)
	e2e.SetupCDCFlowStatusQuery(s.t, env, flowConnConfig)
	e2e.EnvWaitForEqualTablesWithNames(
		env, s, "waiting on initial", srcTableName, dstTableName,
		"\"id with Space\",\"column with Space\",\"another column with Space\"",
	)

	_, err = s.Conn().Exec(context.Background(), fmt.Sprintf(`
		INSERT INTO %s ("column with space", "another column with space")
		VALUES ('cdc', 'value');
	`, srcFullName))
	require.NoError(s.t, err)

	e2e.EnvWaitForEqualTablesWithNamesDifferentColumns(
		env, s, "waiting on cdc", srcTableName, dstTableName,
		"\"id with Space\",\"column with Space\",\"another column with Space\"",
		"id_with_Space,column_with_Space,another_column_with_Space",
	)

	env.Cancel()
	e2e.RequireEnvCanceled(s.t, env)
}
