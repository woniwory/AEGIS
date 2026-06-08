package com.example.forensic.Service;

import com.example.forensic.Entity.Log;
import com.example.forensic.Entity.Message;
import com.itextpdf.kernel.colors.Color;
import com.itextpdf.kernel.colors.DeviceGray;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.borders.SolidBorder;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Value;

@Service
public class reportService {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Value("${report.dir:/app/reports}")
    private String directoryPath;

    @Autowired
    HashService hashService;


    public String generateReport(String deviceId, List<Log> logs, LocalDateTime startTime, LocalDateTime endTime) throws Exception {
        Map<String, Color> logTypeColors = new HashMap<>();
        logTypeColors.put("AntiForensicLog", new DeviceRgb(255, 200, 245));
        logTypeColors.put("CallingLog", new DeviceRgb(103, 153, 255));
        logTypeColors.put("BluetoothLog", new DeviceRgb(134, 229, 127));
        logTypeColors.put("MessageLog", new DeviceRgb(250, 237, 125));
        logTypeColors.put("FileLog", new DeviceRgb(153, 255, 204));
        logTypeColors.put("AppExecutionLog", new DeviceRgb(239, 139, 71));

        String fileName = "custom_report_" + deviceId + ".pdf";
        String filePath = directoryPath + "/" + fileName;

        Files.createDirectories(Paths.get(directoryPath));

        Map<String, List<Log>> groupedLogs = logs.stream()
                .filter(log -> log.getMessage().stream()
                        .map(Message::getDeviceTimestamp)
                        .min(LocalDateTime::compareTo)
                        .filter(timestamp -> !timestamp.isBefore(startTime) && !timestamp.isAfter(endTime))
                        .isPresent())
                .collect(Collectors.groupingBy(Log::getHash));

        StringBuilder hashValidationReport = new StringBuilder();
        boolean isAnyHashInvalid = false;

        for (Map.Entry<String, List<Log>> entry : groupedLogs.entrySet()) {
            String expectedHash = entry.getKey();
            // 같은 hash를 가진 Log가 중복 업로드되어 여러 개 존재할 수 있으므로
            // 첫 번째 Log 하나만 사용하여 메시지가 2배로 집계되는 것을 방지
            Log representativeLog = entry.getValue().get(0);

            StringBuilder logsContent = new StringBuilder();

            for (Message msg : representativeLog.getMessage()) {
                logsContent.append(msg.getDeviceTimestamp().format(FORMATTER))
                        .append(" ")
                        .append(msg.getContent());

                if (msg.getServerTimestamp() != null) {
                    logsContent.append(" ; serverTimestamp: ");
                    if (msg.isEstimatedServerTimestamp()) logsContent.append("[estimated] ");
                    logsContent.append(msg.getServerTimestamp().format(FORMATTER));
                }
                if (msg.getTransmissionTimestamp() != null) {
                    logsContent.append(" ; transmissionTimestamp: ")
                            .append(msg.getTransmissionTimestamp().format(FORMATTER));
                }

                logsContent.append("\n");
            }

            String logFileName = "logs_" + expectedHash + ".txt";
            Path logFilePath = Paths.get(directoryPath, logFileName);
            Files.write(logFilePath, logsContent.toString().getBytes(StandardCharsets.UTF_8));

            String calculatedFileHash = hashService.calculateFileHash(logFilePath);

            if (!expectedHash.equals(calculatedFileHash)) {
                isAnyHashInvalid = true;
                hashValidationReport.append(String.format("[Warning] Hash mismatch! Expected: %s, Found: %s\n", expectedHash, calculatedFileHash));
            }
        }

        String hashStatus = isAnyHashInvalid ? "[Warning] Hash integrity issue, log analysis cannot proceed.\n"
                : "[Success] Hash integrity verification completed. All logs have valid hash values.\n";
        hashValidationReport.append(hashStatus);

        try (PdfWriter writer = new PdfWriter(new FileOutputStream(filePath));
             PdfDocument pdf = new PdfDocument(writer);
             Document document = new Document(pdf)) {

            document.add(new Paragraph("Device Log Report: " + deviceId)
                    .setBold().setFontSize(16)
                    .setMarginBottom(10));

            document.add(new Paragraph("⏳ Duration: " + startTime.format(FORMATTER) + " ~ " + endTime.format(FORMATTER))
                    .setFontSize(12)
                    .setMarginBottom(20));

            document.add(new Paragraph(hashValidationReport.toString())
                    .setFontSize(12)
                    .setMarginBottom(20));

            Map<String, String[][]> keywordMappings = new HashMap<>();
            keywordMappings.put("AntiForensicLog", new String[][]{
                    {"Timestamp manipulation", "Anti-forensic event detected:", ""},
                    {"Timestamp manipulation", "SystemClockTime: Setting time of day to sec=", ""},
                    {"Timestamp manipulation", "Before System Time:", ""},
                    {"Timestamp manipulation", "Auto time setting enabled:", ""},
                    {"ADB logcat -c", "Log Buffer Cleared Detected. (adb logcat -c)", ""},
                    {"Power Off or Reboot", "Device Shutdown or Reboot Detected.", ""},
            });
            keywordMappings.put("CallingLog", new String[][]{
                    {"Termination of the call", "Termination of the call", ""},
                    {"Refuse incoming calls or don't answer", "Refuse incoming calls or don't answer", ""},
                    {"start an incoming call", "start an incoming call", ""},
                    {"start an outgoing call", "start an outgoing call", ""},
                    {"Ringing an incoming call", "Ringing an incoming call", ""},
                    {"Ringing an outgoing call", "Ringing an outgoing call", ""},
            });
            keywordMappings.put("BluetoothLog", new String[][]{
                    {"connect Bluetooth", "Bluetooth connected to:", ""},
                    {"disconnect Bluetooth", "Bluetooth disconnected to:", ""},
                    {"start streaming", "A2DP streaming started on device:", ""},
                    {"stop streaming", "A2DP streaming stopped on device:", ""},
            });
            keywordMappings.put("MessageLog", new String[][]{
                    {"send/receive SMS", "SMS Sent to/from:", ""},
                    {"send/receive SMS", "SMS Sent to:", ""},
                    {"send/receive SMS", "SMS Sent from:", ""},
                    {"send/receive SMS", "SMS Received from:", ""},
            });
            keywordMappings.put("FileLog", new String[][]{
                    {"File Opened", "File Opened (file_opened):", ""},
                    {"File Closed without Writing", "File Closed without Writing (closed_without_writing):", ""},
                    {"File Closed after Writing", "File Closed after Writing (closed_after_write):", ""},
                    {"File Accessed (Read)", "File Accessed (read_from):", ""},
                    {"File Revised (Written)", "File Revised (written_to):", ""},
                    {"MediaStore Changed:", "MediaStore changed:", ""},
                    {"File Metadata Changed:", "File Metadata Changed:", ""},
                    {"File Events", "File Name (DISPLAY_NAME)", ""},
                    {"File Events", "Relative Path", ""},
                    {"File Modified After Date", "Modified After Date", ""},
                    {"File Created", "File Created", ""},
                    {"File Deleted", "File Deleted", ""},
            });
            keywordMappings.put("AppExecutionLog", new String[][]{
                    {"App moved to background", "Background App:", ""},
                    {"App moved to foreground", "Foreground App:", ""},
                    {"Text clicked", "Text:", ""},
                    {"Content description", "Content Description:", ""},
                    {"Class name", "Class Name:", ""},
                    {"Is clickable", "Clickable:", ""},
                    {"Is enabled", "Enabled:", ""},
                    {"Is focusable", "Focusable:", ""},
            });

            // 로그 테이블 출력 순서 지정
            List<String> logTypeOrder = List.of(
                    "AntiForensicLog",
                    "CallingLog",
                    "MessageLog",
                    "BluetoothLog",
                    "FileLog",
                    "AppExecutionLog"
            );

            // server timestamp 오름차순, null 맨 뒤, 동점이면 device timestamp 2차 정렬
            Comparator<MessageWrapper> timelineComparator = (a, b) -> {
                LocalDateTime aSrv = a.message.getServerTimestamp();
                LocalDateTime bSrv = b.message.getServerTimestamp();
                if (aSrv == null && bSrv == null) return a.message.getDeviceTimestamp().compareTo(b.message.getDeviceTimestamp());
                if (aSrv == null) return 1;
                if (bSrv == null) return -1;
                int cmp = aSrv.compareTo(bSrv);
                if (cmp != 0) return cmp;
                return a.message.getDeviceTimestamp().compareTo(b.message.getDeviceTimestamp());
            };

            // 로그 테이블 컬럼 너비 (Event Type, Details, Occurrence)
            float[] columnWidths = {4, 6, 3};

            for (String logType : logTypeOrder) {
                String[][] keywordMap = keywordMappings.get(logType);
                if (keywordMap == null) continue;

                List<MessageWrapper> messages = logs.stream()
                        .filter(log -> log.getLogType().equals(logType))
                        .flatMap(log -> log.getMessage().stream()
                                .map(msg -> new MessageWrapper(log.getLogType(), log.getHash(), msg)))
                        .sorted(timelineComparator)
                        .collect(Collectors.toList());

                List<MessageWrapper> matchedMessages = messages.stream()
                        .filter(wrapper -> Arrays.stream(keywordMap)
                                .anyMatch(row -> wrapper.message.getContent().contains(row[1])))
                        .collect(Collectors.toList());

                if (matchedMessages.isEmpty()) continue;

                document.add(new Paragraph(logType).setBold().setFontSize(16).setMarginTop(20).setMarginBottom(10));

                Table table = new Table(UnitValue.createPercentArray(columnWidths))
                        .useAllAvailableWidth();

                // 헤더 스타일
                String[] headers = {"Event Type", "Details", "Occurrence"};
                for (String header : headers) {
                    Cell cell = new Cell().add(new Paragraph(header)
                                    .setBold()
                                    .setTextAlignment(TextAlignment.CENTER)
                                    .setMultipliedLeading(1.2f))
                            .setBackgroundColor(new DeviceGray(0.85f))
                            .setBorder(new SolidBorder(0.5f))
                            .setPadding(5);
                    table.addHeaderCell(cell);
                }

                for (MessageWrapper wrapper : matchedMessages) {
                    Optional<String[]> matchedRow = Arrays.stream(keywordMap)
                            .filter(row -> wrapper.message.getContent().contains(row[1]))
                            .findFirst();

                    matchedRow.ifPresent(row -> {
                        Color bgColor = logTypeColors.getOrDefault(logType, new DeviceGray(0.85f));
                        String wrappedContent = wrapTextEveryNChars(wrapper.message.getContent(), 65);

                        table.addCell(new Cell().add(new Paragraph(row[0]))
                                .setBackgroundColor(bgColor));
                        table.addCell(new Cell().add(new Paragraph(wrappedContent))
                                .setBackgroundColor(bgColor));
                        table.addCell(new Cell().add(new Paragraph(wrapper.message.getDeviceTimestamp().format(FORMATTER)))
                                .setBackgroundColor(bgColor));
                    });
                }


                document.add(table);
            }

            // Reconstructing Timeline Section
            document.add(new Paragraph("\nReconstructing Timeline").setBold().setFontSize(16).setMarginTop(30).setMarginBottom(10));

            // Reconstructing Timeline 테이블 컬럼 너비
            float[] timelineColumnWidths = {3f, 5f, 3f, 3f};

            Table timelineTable = new Table(UnitValue.createPercentArray(timelineColumnWidths))
                    .useAllAvailableWidth();

            String[] timelineHeaders = {"Device Timestamp", "Message", "Server Timestamp", "Transmission Timestamp"};
            for (String header : timelineHeaders) {
                Cell cell = new Cell().add(new Paragraph(header)
                                .setBold()
                                .setFontSize(12)
                                .setTextAlignment(TextAlignment.CENTER))
                        .setBackgroundColor(new DeviceGray(0.85f))
                        .setBorder(new SolidBorder(0.5f))
                        .setPadding(5);
                timelineTable.addHeaderCell(cell);
            }

            List<MessageWrapper> allMessagesSorted = logs.stream()
                    .flatMap(log -> log.getMessage().stream()
                            .map(msg -> new MessageWrapper(log.getLogType(), log.getHash(), msg)))
                    .sorted(timelineComparator)
                    .collect(Collectors.toList());

            // transmissionTimestamp별 가장 늦은 deviceTimestamp 계산 (추정을 위해)
            Map<LocalDateTime, LocalDateTime> maxDeviceTsMap = new HashMap<>();
            for (Log log : logs) {
                for (Message msg : log.getMessage()) {
                    if (msg.getTransmissionTimestamp() != null) {
                        LocalDateTime currentMax = maxDeviceTsMap.get(msg.getTransmissionTimestamp());
                        if (currentMax == null || msg.getDeviceTimestamp().isAfter(currentMax)) {
                            maxDeviceTsMap.put(msg.getTransmissionTimestamp(), msg.getDeviceTimestamp());
                        }
                    }
                }
            }

            for (MessageWrapper wrapper : allMessagesSorted) {
                Message msg = wrapper.message;
                Color bgColor = logTypeColors.getOrDefault(wrapper.logType, new DeviceGray(0.85f));

                timelineTable.addCell(new Cell().add(new Paragraph(msg.getDeviceTimestamp().format(FORMATTER)))
                        .setBackgroundColor(bgColor).setPadding(5));

                String wrappedContent = wrapTextEveryNChars(msg.getContent(), 65);
                timelineTable.addCell(new Cell().add(new Paragraph(wrappedContent))
                        .setBackgroundColor(bgColor).setPadding(5));

                // Server Timestamp (추정값이면 [Offline\nEstimated] 표기)
                String serverTsStr = "N/A";
                if (msg.getServerTimestamp() != null) {
                    serverTsStr = (msg.isEstimatedServerTimestamp() ? "[Offline\nEstimated]\n" : "")
                            + msg.getServerTimestamp().format(FORMATTER);
                } else if (msg.getTransmissionTimestamp() != null) {
                    LocalDateTime maxDeviceTs = maxDeviceTsMap.get(msg.getTransmissionTimestamp());
                    if (maxDeviceTs != null) {
                        Duration diff = Duration.between(msg.getDeviceTimestamp(), maxDeviceTs);
                        LocalDateTime estimatedServerTs = msg.getTransmissionTimestamp().minus(diff);
                        serverTsStr = "[Offline\nEstimated]\n" + estimatedServerTs.format(FORMATTER);
                    }
                }
                timelineTable.addCell(new Cell().add(new Paragraph(serverTsStr).setFontSize(9))
                        .setBackgroundColor(bgColor).setPadding(5));

                // Transmission Timestamp (오프라인→온라인 플러시 시각)
                String transmissionTsStr = msg.getTransmissionTimestamp() != null
                        ? msg.getTransmissionTimestamp().format(FORMATTER)
                        : "-";
                timelineTable.addCell(new Cell().add(new Paragraph(transmissionTsStr).setFontSize(9))
                        .setBackgroundColor(bgColor).setPadding(5));
            }

            document.add(timelineTable);

            document.close();
        }

        return filePath;
    }

    // 메시지 래퍼 클래스 (내부 클래스 등 적절히 배치)
    private static class MessageWrapper {
        String logType;
        String hash;
        Message message;

        public MessageWrapper(String logType, String hash, Message message) {
            this.logType = logType;
            this.hash = hash;
            this.message = message;
        }
    }

    /**
     * estimatedTimestamp 계산 메서드
     * 필요시 내부 로직 변경 가능
     */
    private String calculateEstimatedTimestamp(LocalDateTime kstServerTimestamp, LocalDateTime createdAt) {
        if (kstServerTimestamp != null && createdAt != null) {

            // serverTimestamp와 createdAt 사이의 차이 계산
            Duration duration = Duration.between(createdAt, kstServerTimestamp);

            // createdAt에 차이를 더한 보정 시간 계산
            LocalDateTime estimatedDateTime = createdAt.plus(duration);

            return estimatedDateTime.format(FORMATTER);
        } else if (kstServerTimestamp != null) {
            return kstServerTimestamp.format(FORMATTER);
        } else if (createdAt != null) {
            // serverTimestamp가 없고 createdAt만 있다면 그것을 그대로 사용
            return createdAt.format(FORMATTER);
        }
        return "N/A"; // 두 값 모두 없으면 "N/A" 반환
    }


    private String wrapTextEveryNChars(String text, int maxChars) {
        if (text == null || text.length() <= maxChars) return text;
        StringBuilder sb = new StringBuilder();
        int index = 0;
        while (index < text.length()) {
            int end = Math.min(index + maxChars, text.length());
            sb.append(text, index, end).append("\n");
            index = end;
        }
        return sb.toString();
    }





}
