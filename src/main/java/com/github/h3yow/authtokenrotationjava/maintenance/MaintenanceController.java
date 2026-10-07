package com.github.h3yow.authtokenrotationjava.maintenance;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Operational endpoint that triggers one state reclamation sweep. It lives
 * outside {@code /api/**}, so it neither carries a caller identity nor
 * consumes any caller rate-limit quota.
 */
@RestController
@RequestMapping("/internal/maintenance")
public class MaintenanceController {

    private final StateReclamationService reclamationService;

    public MaintenanceController(StateReclamationService reclamationService) {
        this.reclamationService = reclamationService;
    }

    @PostMapping("/purge")
    public CleanupReport purge() {
        return reclamationService.purgeNow();
    }
}
