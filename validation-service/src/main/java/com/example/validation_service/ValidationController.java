package com.example.validation_service;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class ValidationController {

    private final ValidationService service;

    public ValidationController(ValidationService service) {
        this.service = service;
    }

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("history", service.getHistory());
        return "index";
    }

    @PostMapping("/verify")
    public String verify(@RequestParam("document") MultipartFile doc, RedirectAttributes redirectAttributes) {
        try {
            if (doc.isEmpty()) {
                redirectAttributes.addFlashAttribute("errorMessage", "Прикачи документ, сертификат или дигитален потпис!");
                return "redirect:/";
            }

            String fileName = doc.getOriginalFilename();
            boolean isValid = false;
            String lowerName = (fileName != null) ? fileName.toLowerCase() : "";

            if (lowerName.endsWith(".pdf")) {
                isValid = service.validatePdf(doc.getInputStream(), fileName);
            } else if (lowerName.endsWith(".cer") || lowerName.endsWith(".crt") || lowerName.endsWith(".der")) {
                isValid = service.validateStandaloneCertificate(doc.getInputStream(), fileName);
            } else if (lowerName.endsWith(".p7s")) {
                isValid = service.validateP7sSignature(doc.getInputStream(), fileName);
            } else if (lowerName.endsWith(".pptx") || lowerName.endsWith(".docx") || lowerName.endsWith(".xlsx")) {
                isValid = service.validateOfficeDocument(doc.getInputStream(), fileName);
            } else {
                redirectAttributes.addFlashAttribute("errorMessage", "Неподдржан формат! Избери PDF, Office, .cer/.crt или .p7s потпис.");
                return "redirect:/";
            }

            if (isValid) {
                redirectAttributes.addFlashAttribute("message", "Успешна валидација.");
            } else {
                redirectAttributes.addFlashAttribute("errorMessage", "Неуспешна валидација.");
            }
            return "redirect:/";
        } catch (Exception e) {
            e.printStackTrace();
            redirectAttributes.addFlashAttribute("errorMessage", "Грешка при обработка: " + e.getMessage());
            return "redirect:/";
        }
    }
}