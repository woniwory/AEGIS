package com.example.forensic.Repository;

import com.example.forensic.Entity.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.stereotype.Repository;
import org.springframework.data.mongodb.core.query.Query;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public class LogRepository {

    @Autowired
    private MongoTemplate mongoTemplate;

    // 동적으로 컬렉션 이름을 받아서 로그 저장
    public void save(Log log) {
        mongoTemplate.save(log);
    }



    // 동적으로 컬렉션 이름을 받아서 deviceId와 logType을 기준으로 로그 조회
    public List<Log> findByDeviceIdAndLogType(String deviceId, String logType) {
        Query query = new Query();
        query.addCriteria(Criteria.where("deviceId").is(deviceId).and("logType").is(logType));

        return mongoTemplate.find(query, Log.class);
    }




    // 특정 deviceId의 로그를 주어진 기간 내에서 조회

    public List<Log> findLogsWithinDuration(String deviceId, LocalDateTime startTime, LocalDateTime endTime) {
        // LocalDateTime과 MongoDB UTC 저장값 간 timezone 불일치를 피하기 위해
        // DB 쿼리는 deviceId만으로 조회하고, 시간 필터링은 Java 레벨에서 수행
        Query query = new Query();
        query.addCriteria(Criteria.where("deviceId").is(deviceId));
        List<Log> all = mongoTemplate.find(query, Log.class);

        // message의 deviceTimestamp 기준으로 시간 범위 내 로그만 반환
        return all.stream()
                .filter(log -> log.getMessage() != null && log.getMessage().stream()
                        .anyMatch(msg -> msg.getDeviceTimestamp() != null
                                && !msg.getDeviceTimestamp().isBefore(startTime)
                                && !msg.getDeviceTimestamp().isAfter(endTime)))
                .collect(java.util.stream.Collectors.toList());
    }

    public List<Log> findAll() {
        return mongoTemplate.findAll(Log.class);
    }

    public void deleteById(String id) {
        Query query = new Query(Criteria.where("id").is(id));
        mongoTemplate.remove(query, Log.class);
    }

    public void deleteAll() {
        mongoTemplate.remove(new Query(), Log.class);
    }
}



