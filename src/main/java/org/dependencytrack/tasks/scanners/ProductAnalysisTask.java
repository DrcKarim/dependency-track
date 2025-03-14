/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.tasks.scanners;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.event.ProductAnalysisEvent;

import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ProductAnalysisTask extends AbstractVulnerableSoftwareAnalysisTask implements Subscriber {
    private static final Logger LOGGER = Logger.getLogger(ProductAnalysisTask.class);
    private VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel;

    @Override
    public void inform(final Event e) {
        if (e instanceof ProductAnalysisEvent) {
            if (!super.isEnabled(ConfigPropertyConstants.SCANNER_PRODUCT_ENABLED)) {
                return;
            }
            final ProductAnalysisEvent event = (ProductAnalysisEvent)e;
            vulnerabilityAnalysisLevel = event.analysisLevel();
            LOGGER.info("Starting product analysis task");
            if (!event.components().isEmpty()) {
                analyze(event.components());
            }
            LOGGER.info("product analysis complete");
        }
    }


    @Override
    public AnalyzerIdentity getAnalyzerIdentity() {
        return AnalyzerIdentity.PRODUCT_ANALYZER;
       // return null;
    }

    @Override
    public void analyze(List<Component> components) {

        try (QueryManager qm = new QueryManager()) {
            LOGGER.info("Analyzing Product " + components.size() + " component(s)");
            for (final Component c : components) {
                final Component component = qm.getObjectByUuid(Component.class, c.getUuid()); // Refresh component and attach to current pm.
                if (component == null) continue;
                if (component.getProductId() != null && qm.doesProductIdExist(component.getProductId()) ) {
                    LOGGER.info("Inside the filter in ProductAnalysis");
                    LOGGER.info("Component " + component.getName() + " has a Product ID: " + component.getProductId() + ". Running product analysis.");
                  ProductAnalysis(qm, component.getProductId(),component);
                }
                else {
                    LOGGER.info("Component " + component.getName() + " has a unique Product ID or no Product ID. Running normal analysis.");
                }

            }
            LOGGER.info("End Product Analyzing " + components.size() + " component(s)");
        }
     }


    @Override
    public boolean isCapable(Component component) {
         if(component.getProductId() == null) return false;
         else return true;
    }


public void ProductAnalysis(QueryManager qm, String productId, Component component) {
    LOGGER.info("Inside assignVulnerabilitiesToComponent for Product ID: " + productId);
    if (StringUtils.isBlank(productId) || component == null) {
        LOGGER.warn("Invalid input: Product ID or Component is null");
        return;
    }
    try {
        // Step 1: Get the UUID of the project using the Product ID
        String projectUuid = qm.getProjectUuidByProductId(productId);
        if (projectUuid == null) {
            LOGGER.warn("No project found for Product ID: " + productId);
            return;
        }
        // Step 2: Get the project object using the UUID
        Project project = qm.getProject(projectUuid);
        if (project == null) {
            LOGGER.warn("No project object found for UUID: " + projectUuid);
            return;
        }

        // Step 3: Get vulnerabilities linked to the project (all vulnerabilities the product has)
        List<Vulnerability> projectVulnerabilities = qm.getVulnerabilities(project, false);
        Set<Vulnerability> projectVulnSet = new HashSet<>(projectVulnerabilities);
        LOGGER.info("Found " + projectVulnerabilities.size() + " vulnerabilities for Project UUID: " + projectUuid);

        // Step 4: Get vulnerabilities already assigned to the component
        List<Vulnerability> componentVulnerabilities = qm.getAllVulnerabilities(component, false);
        Set<Vulnerability> componentVulnSet = new HashSet<>(componentVulnerabilities);
        LOGGER.info("Component already has " + componentVulnerabilities.size() + " vulnerabilities");

        // Step 5: Find the vulnerabilities that are in projectVulnSet but NOT in componentVulnSet
        Set<Vulnerability> newVulnerabilities = new HashSet<>(projectVulnSet); // Copy of project vulnerabilities
        newVulnerabilities.removeAll(componentVulnSet); // Remove already assigned vulnerabilities

        LOGGER.info("Adding " + newVulnerabilities.size() + " new vulnerabilities to component " + component.getName());

        // Step 6: Assign only the new vulnerabilities to the component
        int addedCount = 0;
        for (Vulnerability v : newVulnerabilities) {
            // Ensure we use the existing vulnerability object if already in the database
            Vulnerability existingVulnerability = qm.getVulnerabilityByVulnId(v.getSource(), v.getVulnId());
            if (existingVulnerability == null) {
                LOGGER.info("Adding new vulnerability to DB: " + v.getVulnId());
                existingVulnerability = qm.synchronizeVulnerability(v, true);
            }

            qm.addVulnerability(existingVulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
            addedCount++;
        }
        LOGGER.info("Successfully linked " + addedCount + " new vulnerabilities to component " + component.getName());

    } catch (Exception e) {
        LOGGER.error("Error assigning vulnerabilities to component", e);
    }

 }

}
