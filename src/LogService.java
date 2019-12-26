import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.time.Instant;
import java.time.LocalDateTime;

public class LogService {

    private File logFile;

    public LogService() {
        if (!(new File("./logs")).exists()) {
            new File("./logs").mkdir();
        }
        logFile = new File("./logs/LogFile" + Instant.now() +  ".log");
    }

    public LogService(String logPath) throws NoSuchFileException {
        logFile = new File(logPath);
        if (!logFile.exists()) {
            throw new NoSuchFileException("Failed to find File from given path: " + logPath);
        }
    }

    public synchronized boolean addLog(LocalDateTime t, String id, String msg) throws IOException {
        
        String logMsg = new String(t.toString() + " " + id + " {" + msg + "}\n");

        BufferedWriter writer = new BufferedWriter(new FileWriter(logFile, true));
        writer.write(logMsg);
        writer.close();
        
        return true;
    }
}