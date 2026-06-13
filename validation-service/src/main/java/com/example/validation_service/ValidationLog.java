package com.example.validation_service;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "validation_logs")
public class ValidationLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String fileName;
    private String signerName;
    private boolean isValid;
    private LocalDateTime validationTime;


    public void setId(Long id) { this.id = id; }
    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }
    public String getSignerName() { return signerName; }
    public void setSignerName(String signerName) { this.signerName = signerName; }
    public boolean isValid() { return isValid; }
    public void setValid(boolean valid) { isValid = valid; }
    public LocalDateTime getValidationTime() { return validationTime; }
    public void setValidationTime(LocalDateTime validationTime) { this.validationTime = validationTime; }
}