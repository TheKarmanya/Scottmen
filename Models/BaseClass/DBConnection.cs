using MySqlConnector;
namespace BaseClass
{
    /// <summary>
    /// Summary description for db_connection
    /// </summary>
    public class DBConnection
    {
        public MySqlDataAdapter? Adapter;
        public MySqlDataReader? reader;
        public MySqlCommand? command;
        public MySqlParameter? objMySqlParameter;
        private string connectionString;
        public DBConnection()
        {
            connectionString = GetConnectionString(DBConnectionList.TransactionDb);
        }
        public DBConnection(DBConnectionList dBConnectionList)
        {
            connectionString = GetConnectionString(dBConnectionList);
        }

        #region Select Query without parameter
        /// <summary>
        /// Select query with default connection string without parameter
        /// </summary>
        /// <param name="_query"></param>
        /// <returns></returns>
        private ReturnClass.ReturnDataTable ExecuteSelectQuery(string _query)
        {
            ReturnClass.ReturnDataTable dt = new();
            try
            {
                using MySqlConnection connection = new(connectionString);
                using MySqlCommand cmd = new();
                connection.Open();
                cmd.Connection = connection;
                cmd.CommandText = _query;
                using (Adapter = new MySqlDataAdapter())
                {
                    Adapter.SelectCommand = cmd;
                    Adapter.Fill(dt.table);
                    dt.status = true;
                }
            }
            catch (MySqlException ex)
            {
                WriteLog.Error("ExecuteSelectQuery - Query: " + _query + "\n   error - ", ex);
                dt.status = false;
                dt.message = ex.Message;
            }
            return dt;
        }

        /// <summary>
        /// Async Select query with default connection string without parameter
        /// </summary>
        /// <param name="_query"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnDataTable> ExecuteSelectQueryAsync(string _query)
        {
            return await Task.Run(() => ExecuteSelectQuery(_query));

            #region Commented because mysqlconnector doesn't support async for dataadapter
            //ReturnClass.ReturnDataTable dt = new();
            //try
            //{
            //    using MySqlConnection connection = new(connectionString);
            //    using MySqlCommand cmd = new();
            //    connection.Open();
            //    cmd.Connection = connection;
            //    cmd.CommandText = _query;

            //    using (Adapter = new MySqlDataAdapter())
            //    {
            //        Adapter.SelectCommand = cmd;
            //        Adapter.Fill(dt.table);
            //        dt.status = true;
            //    }
            //}
            //catch (MySqlException ex)
            //{
            //    WriteLog.Error("ExecuteSelectQueryAsync - Query: " + _query + "\n   error - ", ex);
            //    dt.status = false;
            //    dt.message = ex.Message;
            //}
            //return dt;
            #endregion
        }

        /// <summary>
        /// Select query with custom connection string without parameter
        /// </summary>
        /// <param name="_query"></param>
        /// <param name="dbconname"></param>
        /// <returns></returns>
        private ReturnClass.ReturnDataTable ExecuteSelectQuery(string _query, DBConnectionList dbconname)
        {
            ReturnClass.ReturnDataTable dt = new();
            try
            {
                string connectionString = GetConnectionString(dbconname);
                using MySqlConnection connection = new(connectionString);
                using MySqlCommand cmd = new();
                connection.Open();
                cmd.Connection = connection;
                cmd.CommandText = _query;
                using (Adapter = new MySqlDataAdapter())
                {
                    Adapter.SelectCommand = cmd;
                    Adapter.Fill(dt.table);
                    dt.status = true;
                }
            }
            catch (MySqlException ex)
            {
                WriteLog.Error("ExecuteSelectQuery - Query: " + _query + "\n   error - ", ex);
                dt.status = false;
                dt.message = ex.Message;
            }
            return dt;
        }

        /// <summary>
        /// Async Select query with custom connection string without parameter
        /// </summary>
        /// <param name="_query"></param>
        /// <param name="dbconname"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnDataTable> ExecuteSelectQueryAsync(string _query, DBConnectionList dbconname)
        {
            return await Task.Run(() => ExecuteSelectQuery(_query, dbconname));
            #region Commented Because mysqlconnector doesn't support async opration in dataadapter
            //ReturnClass.ReturnDataTable dt = new();
            //try
            //{
            //    string connectionString = GetConnectionString(dbconname);
            //    using MySqlConnection connection = new(connectionString);
            //    using MySqlCommand cmd = new();
            //    connection.Open();
            //    cmd.Connection = connection;
            //    cmd.CommandText = _query;
            //    using (Adapter = new MySqlDataAdapter())
            //    {
            //        Adapter.SelectCommand = cmd;
            //        Adapter.Fill(dt.table);
            //        dt.status = true;
            //    }
            //}
            //catch (MySqlException ex)
            //{
            //    WriteLog.Error("ExecuteSelectQueryAsync - Query: " + _query + "\n   error - ", ex);
            //    dt.status = false;
            //    dt.message = ex.Message;
            //}
            //return dt;
            #endregion
        }
        #endregion

        #region Select Query with parameter 

        /// <summary>
        /// Execute Select Query With Parameters
        /// </summary>
        /// <param name="_query"></param>
        /// <param name="sqlParameter"></param>
        /// <returns></returns>
        private ReturnClass.ReturnDataTable ExecuteSelectQuery(string _query, MySqlParameter[] sqlParameter)
        {
            ReturnClass.ReturnDataTable dt = new();
            try
            {
                using MySqlConnection connection = new(connectionString);
                using MySqlCommand cmd = new();
                connection.Open();
                cmd.Connection = connection;
                cmd.CommandText = _query;
                cmd.Parameters.Clear();
                cmd.Parameters.AddRange(sqlParameter);

                using (Adapter = new MySqlDataAdapter())
                {
                    Adapter.SelectCommand = cmd;
                    Adapter.Fill(dt.table);
                    dt.status = true;
                }
            }
            catch (MySqlException ec)
            {
                WriteLog.Error("ExecuteSelectQuery - Query: " + _query + "\n   error - ", ec);
                dt.status = false;
                dt.message = ec.Message;
            }
            return dt;
        }
        /// <summary>
        /// Async select query with parameter
        /// </summary>
        /// <param name="_query"></param>
        /// <param name="sqlParameter"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnDataTable> ExecuteSelectQueryAsync(string _query, MySqlParameter[] sqlParameter)
        {
            return await Task.Run(() => ExecuteSelectQuery(_query, sqlParameter));
            #region Commented Because mysqlconnector doesn't support async opration in dataadapter
            //ReturnClass.ReturnDataTable dt = new();
            //try
            //{
            //    using MySqlConnection connection = new(connectionString);
            //    using MySqlCommand cmd = new();
            //    connection.Open();
            //    cmd.Connection = connection;
            //    cmd.CommandText = _query;
            //    cmd.Parameters.Clear();
            //    cmd.Parameters.AddRange(sqlParameter);

            //    using (Adapter = new MySqlDataAdapter())
            //    {
            //        Adapter.SelectCommand = cmd;
            //        Adapter.Fill(dt.table);
            //        dt.status = true;
            //    }
            //}
            //catch (MySqlException ec)
            //{
            //    WriteLog.Error("ExecuteSelectQueryAsync - Query: " + _query + "\n   error - ", ec);
            //    dt.status = false;
            //    dt.message = ec.Message;
            //}
            //return dt;
            #endregion
        }

        /// <summary>
        /// select query with parameter and custom connection string
        /// </summary>
        /// <param name="_query"></param>
        /// <param name="sqlParameter"></param>
        /// <param name="dbconname"></param>
        /// <returns></returns>
        private ReturnClass.ReturnDataTable ExecuteSelectQuery(string _query, MySqlParameter[] sqlParameter, DBConnectionList dbconname)
        {
            ReturnClass.ReturnDataTable dt = new();
            try
            {
                using MySqlConnection connection = new(GetConnectionString(dbconname));
                using MySqlCommand cmd = new();
                connection.Open();
                cmd.Connection = connection;
                cmd.CommandText = _query;
                cmd.Parameters.Clear();
                cmd.Parameters.AddRange(sqlParameter);

                using (Adapter = new MySqlDataAdapter())
                {
                    Adapter.SelectCommand = cmd;
                    Adapter.Fill(dt.table);
                    dt.status = true;
                }
            }
            catch (MySqlException ec)
            {
                WriteLog.Error("ExecuteSelectQuery - Query: " + _query + "\n   error - ", ec);
                dt.status = false;
                dt.message = ec.Message;
            }
            return dt;
        }

        /// <summary>
        /// Async select Query with parameter and custom connection string
        /// </summary>
        /// <param name="_query"></param>
        /// <param name="sqlParameter"></param>
        /// <param name="dbconname"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnDataTable> ExecuteSelectQueryAsync(string _query, MySqlParameter[] sqlParameter, DBConnectionList dbconname)
        {
            return await Task.Run(() => ExecuteSelectQuery(_query, sqlParameter, dbconname));
            #region Commented Because mysqlconnector doesn't support async opration in dataadapter
            //ReturnClass.ReturnDataTable dt = new();
            //try
            //{
            //    using MySqlConnection connection = new(GetConnectionString(dbconname));
            //    using MySqlCommand cmd = new();
            //    connection.Open();
            //    cmd.Connection = connection;
            //    cmd.CommandText = _query;
            //    cmd.Parameters.Clear();
            //    cmd.Parameters.AddRange(sqlParameter);

            //    using (Adapter = new MySqlDataAdapter())
            //    {
            //        Adapter.SelectCommand = cmd;
            //        Adapter.Fill(dt.table);
            //        dt.status = true;
            //    }
            //}
            //catch (MySqlException ec)
            //{
            //    WriteLog.Error("ExecuteSelectQueryAsync - Query: " + _query + "\n   error - ", ec);
            //    dt.status = false;
            //    dt.message = ec.Message;
            //}
            //return dt;
            #endregion
        }

        #region Select Query With Return DataSet
        /// <summary>
        /// select query with parameter and custom connection string
        /// </summary>
        /// <param name="_query"></param>
        /// <param name="sqlParameter"></param>
        /// <param name="dbconname"></param>
        /// <returns></returns>
        private ReturnClass.ReturnDataSet ExecuteSelectQueryDataSet(string _query, MySqlParameter[] sqlParameter)
        {
            ReturnClass.ReturnDataSet dt = new();
            try
            {
                using MySqlConnection connection = new(connectionString);
                using MySqlCommand cmd = new();
                connection.Open();
                cmd.Connection = connection;
                cmd.CommandText = _query;
                cmd.Parameters.Clear();
                cmd.Parameters.AddRange(sqlParameter);

                using (Adapter = new MySqlDataAdapter())
                {
                    Adapter.SelectCommand = cmd;
                    Adapter.Fill(dt.dataset);
                    dt.status = true;
                }
            }
            catch (MySqlException ec)
            {
                WriteLog.Error("ExecuteSelectQuery - Query: " + _query + "\n   error - ", ec);
                dt.status = false;
                dt.message = ec.Message;
            }
            return dt;
        }

        /// <summary>
        /// Async select Query with parameter and custom connection string
        /// </summary>
        /// <param name="_query"></param>
        /// <param name="sqlParameter"></param>
        /// <param name="dbconname"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnDataSet> ExecuteSelectQueryAsyncDataSet(string _query, MySqlParameter[] sqlParameter)
        {
            return await Task.Run(() => ExecuteSelectQueryDataSet(_query, sqlParameter));
        }

        /// <summary>
        /// select query with parameter and custom connection string
        /// </summary>
        /// <param name="_query"></param>
        /// <param name="sqlParameter"></param>
        /// <param name="dbconname"></param>
        /// <returns></returns>
        private ReturnClass.ReturnDataSet ExecuteSelectQueryDataSet(string _query, MySqlParameter[] sqlParameter, DBConnectionList dbconname)
        {
            ReturnClass.ReturnDataSet dt = new();
            try
            {
                using MySqlConnection connection = new(GetConnectionString(dbconname));
                using MySqlCommand cmd = new();
                connection.Open();
                cmd.Connection = connection;
                cmd.CommandText = _query;
                cmd.Parameters.Clear();
                cmd.Parameters.AddRange(sqlParameter);

                using (Adapter = new MySqlDataAdapter())
                {
                    Adapter.SelectCommand = cmd;
                    Adapter.Fill(dt.dataset);
                    dt.status = true;
                }
            }
            catch (MySqlException ec)
            {
                WriteLog.Error("ExecuteSelectQuery - Query: " + _query + "\n   error - ", ec);
                dt.status = false;
                dt.message = ec.Message;
            }
            return dt;
        }

        /// <summary>
        /// Async select Query with parameter and custom connection string
        /// </summary>
        /// <param name="_query"></param>
        /// <param name="sqlParameter"></param>
        /// <param name="dbconname"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnDataSet> ExecuteSelectQueryAsyncDataSet(string _query, MySqlParameter[] sqlParameter, DBConnectionList dbconname)
        {
            return await Task.Run(() => ExecuteSelectQueryDataSet(_query, sqlParameter, dbconname));
        }
        #endregion
        #endregion

        #region Common Query Execution Functions
        /// <summary>
        /// Execute Async Transactional Queries
        /// </summary>
        /// <param name="_query"></param>
        /// <param name="sqlParameter"></param>
        /// <param name="methodName"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnBool> ExecuteQueryAsync(string _query, MySqlParameter[] sqlParameter, string methodName)
        {
            ReturnClass.ReturnBool rb = new();
            try
            {
                using MySqlConnection connection = new(connectionString);
                using MySqlCommand cmd = new();
                connection.Open();
                cmd.Connection = connection;
                cmd.CommandText = _query;
                cmd.Parameters.AddRange(sqlParameter);
                await cmd.ExecuteNonQueryAsync();
                rb.status = true;
            }
            catch (MySqlException ex)
            {
                WriteLog.Error(methodName + " - Query: " + _query + "\n   error - ", ex);
                rb.status = false;
                rb.message = ex.Message;
            }
            return rb;
        }
        /// <summary>
        /// Execute Async Transactional Queries
        /// </summary>
        /// <param name="_query"></param>
        /// <param name="sqlParameter"></param>
        /// <param name="methodName"></param>
        /// <param name="ReturnLastInsertedId"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnBool> ExecuteQueryAsync(string _query, MySqlParameter[] sqlParameter, string methodName, bool ReturnLastInsertedId)
        {
            ReturnClass.ReturnBool rb = new();
            try
            {
                using MySqlConnection connection = new(connectionString);
                using MySqlCommand cmd = new();
                connection.Open();
                cmd.Connection = connection;
                cmd.CommandText = _query;
                cmd.Parameters.AddRange(sqlParameter);
                await cmd.ExecuteNonQueryAsync();
                if (ReturnLastInsertedId)
                    rb.value = cmd.LastInsertedId.ToString();
                rb.status = true;
            }
            catch (MySqlException ex)
            {
                WriteLog.Error(methodName + " - Query: " + _query + "\n   error - ", ex);
                rb.status = false;
                rb.message = ex.Message;
            }
            return rb;
        }
        /// <summary>
        /// Execute Async Transactional Queries With Custom DB
        /// </summary>
        /// <param name="_query"></param>
        /// <param name="sqlParameter"></param>
        /// <param name="methodName"></param>
        /// <param name="dbconname"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnBool> ExecuteQueryAsync(string _query, MySqlParameter[] sqlParameter, string methodName, DBConnectionList dbconname)
        {
            ReturnClass.ReturnBool rb = new();
            try
            {
                string connectionString = GetConnectionString(dbl: dbconname);
                using MySqlConnection connection = new(connectionString);
                using MySqlCommand cmd = new();
                connection.Open();
                cmd.Connection = connection;
                cmd.CommandText = _query;
                cmd.Parameters.AddRange(sqlParameter);
                await cmd.ExecuteNonQueryAsync();
                rb.status = true;
            }
            catch (MySqlException exp)
            {
                WriteLog.Error(methodName + " - Query: " + _query + "\n   error - ", exp);
                rb.status = false;
                rb.message = exp.Message;
            }
            return rb;
        }
        /// <summary>
        /// Execute Async Transactional Queries With Custom DB
        /// </summary>
        /// <param name="_query"></param>
        /// <param name="sqlParameter"></param>
        /// <param name="methodName"></param>
        /// <param name="dbconname"></param>
        /// <param name="ReturnLastInsertedId"></param>
        /// <returns></returns>
        public async Task<ReturnClass.ReturnBool> ExecuteQueryAsync(string _query, MySqlParameter[] sqlParameter, string methodName, DBConnectionList dbconname, bool ReturnLastInsertedId)
        {
            ReturnClass.ReturnBool rb = new();
            try
            {
                string connectionString = GetConnectionString(dbl: dbconname);
                using MySqlConnection connection = new(connectionString);
                using MySqlCommand cmd = new();
                connection.Open();
                cmd.Connection = connection;
                cmd.CommandText = _query;
                cmd.Parameters.AddRange(sqlParameter);
                await cmd.ExecuteNonQueryAsync();
                if (ReturnLastInsertedId)
                    rb.value = cmd.LastInsertedId.ToString();
                rb.status = true;
            }
            catch (MySqlException exp)
            {
                WriteLog.Error(methodName + " - Query: " + _query + "\n   error - ", exp);
                rb.status = false;
                rb.message = exp.Message;
            }
            return rb;
        }
        #endregion

        /// <summary>
        /// Returns Connection String
        /// </summary>
        /// <param name="dbl"></param>
        /// <returns></returns>
        private string GetConnectionString(DBConnectionList dbl)
        {
            string connectionStringlocal = "";
            ReturnClass.ReturnBool rb = Utilities.GetAppSettings("Build", "Version");

            if (rb.status)
            {
                string buildType = rb.message!.ToLower();
                
                    connectionStringlocal = dbl switch
                    {
                        DBConnectionList.TransactionDb => Utilities.GetAppSettings("DBConnection", rb.message, "TransactionDB").message!,
                        DBConnectionList.ReportingDb => Utilities.GetAppSettings("DBConnection", rb.message, "ReportingDb").message!,
                        DBConnectionList.TransactionIndustryDB => Utilities.GetAppSettings("DBConnection", rb.message, "TransactionIndustryDB").message!,
                        DBConnectionList.IndustryDB => Utilities.GetAppSettings("DBConnection", rb.message, "IndustryDB").message!,
                        _ => connectionString,
                    };
                }
                
            
            return connectionStringlocal;
        }
    }
}