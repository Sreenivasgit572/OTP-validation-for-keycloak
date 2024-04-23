import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class JDBCExecution {

    String jdbcUrl = "jdbc:postgresql://nidhi-development.cluster-cxk6bpizs4jb.ap-south-1.rds.amazonaws.com:3306/nidhi_dev";
    String username = "admin_nidhi_dev";
    String password = "Adm1nN1dh1D3v";

    // JDBC variables for opening, closing, and managing connection
    Connection connection = null;
    PreparedStatement preparedStatement = null;
    ResultSet resultSet = null;

    public String getAadhaar(String cfmsId) {
        String id = "";
        try {
            connection = DriverManager.getConnection(jdbcUrl, username, password);

            String selectQuery = "select adharid from hrms.employee_personal_ids epi where cfms_id = ?";

            // Create a PreparedStatement with the query
            preparedStatement = connection.prepareStatement(selectQuery);

            // Set any parameters if needed (for example, setting the ID)
            BigDecimal newCfmsId = new BigDecimal(cfmsId);
            preparedStatement.setBigDecimal(1, newCfmsId);

            // Execute the query and get the result set
            resultSet = preparedStatement.executeQuery();

            // Process the result set
            while (resultSet.next()) {
                // Retrieve data from each row
                id = resultSet.getString("adharid");
                // Do something with the retrieved data (print it in this example)
                System.out.println("ID: " + id);
            }

        } catch (
                SQLException e) {
            e.printStackTrace();
        } finally {
            // Close the resources in reverse order of their creation to avoid potential issues
            try {
                if (resultSet != null) {
                    resultSet.close();
                }
                if (preparedStatement != null) {
                    preparedStatement.close();
                }
                if (connection != null) {
                    connection.close();
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        return id;
    }

    public boolean isOtpNeeded(String cfmsId) {
        String id = "";
        try {
            connection = DriverManager.getConnection(jdbcUrl, username, password);

            String selectQuery = "select count(*) as exemption from masters.login_otp_excemption where cfmsid= ? and status is true";

            // Create a PreparedStatement with the query
            preparedStatement = connection.prepareStatement(selectQuery);

            // Set any parameters if needed (for example, setting the ID)
            int newCfmsId = Integer.parseInt(cfmsId);
            preparedStatement.setInt(1, newCfmsId);

            // Execute the query and get the result set
            resultSet = preparedStatement.executeQuery();

            // Process the result set
            while (resultSet.next()) {
                // Retrieve data from each row
                id = resultSet.getString("exemption");
                // Do something with the retrieved data (print it in this example)
                System.out.println("Excemption: " + id);
            }
            if(NonZeroValidation(id)) {
                return true;
            } else {
                return false;
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean NonZeroValidation(String str) {
        boolean flag = true;

        if(str == null || str.equals("") || str.trim() == null || str.trim().equals("") || str.trim().equals("null") || str.trim().equals("0"))
            flag = false;

        return flag;
    }
}