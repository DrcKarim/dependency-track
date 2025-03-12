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
import org.dependencytrack.event.InternalAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.model.VulnerableSoftware;


import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.search.FuzzyVulnerableSoftwareSearchManager;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;

import java.util.Collections;
import java.util.List;

//New added import
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.apache.commons.lang3.StringUtils;

import java.util.Set;
import java.util.HashSet;
/**
 * Subscriber task that performs an analysis of component using internal CPE/PURL data.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public class InternalAnalysisTask extends AbstractVulnerableSoftwareAnalysisTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(InternalAnalysisTask.class);

    public AnalyzerIdentity getAnalyzerIdentity() {
        return AnalyzerIdentity.INTERNAL_ANALYZER;
    }

    private VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel;

    /**
     * {@inheritDoc}
     */
    public void inform(final Event e) {
        if (e instanceof InternalAnalysisEvent) {
            if (!super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_ENABLED)) {
                return;
            }
            final InternalAnalysisEvent event = (InternalAnalysisEvent)e;
            vulnerabilityAnalysisLevel = event.analysisLevel();
            LOGGER.info("Starting internal analysis task");
            if (!event.components().isEmpty()) {
                analyze(event.components());
            }
            LOGGER.info("Internal analysis complete");
        }
    }

    /**
     * Determines if the {@link InternalAnalysisTask} is capable of analyzing the specified Component.
     *
     * @param component the Component to analyze
     * @return true if InternalAnalysisTask should analyze, false if not
     */
    public boolean isCapable(final Component component) {
        return component.getCpe() != null || component.getPurl() != null;
    }


    /**
     * Analyzes a list of Components.
  //   * @param components a list of Components
     */
 /*  public void analyze(final List<Component> components) {
        try (QueryManager qm = new QueryManager()) {
            LOGGER.info("Analyzing " + components.size() + " component(s)");
            for (final Component c : components) {
                final Component component = qm.getObjectByUuid(Component.class, c.getUuid()); // Refresh component and attach to current pm.
                if (component == null) continue;
                versionRangeAnalysis(qm, component);
            }
        }
    }    */
    //   productAnalysisTask(qm , component.getProductId(),component); // Run a copy and paste vulnerabilities from the existing component with the same ID

    /**
     * Analyzes a list of Components.
     * If a component has a duplicated Product ID, it triggers a copy and paste vulnerabilities from this Product ID.
     * Otherwise, it performs a normal version range analysis.
     *
     * @param components a list of Components to analyze.
     */
    public void analyze(final List<Component> components) {
        try (QueryManager qm = new QueryManager()) {
            LOGGER.info("Analyzing " + components.size() + " component(s)");
            for (final Component c : components) {
                final Component component = qm.getObjectByUuid(Component.class, c.getUuid()); // Refresh component and attach to current pm.
                if (component == null) continue;
                if (component.getProductId() != null && qm.doesProductIdExist(component.getProductId()) ) {
                    LOGGER.info("Inside the filter");
                    LOGGER.info("Component " + component.getName() + " has a Product ID: " + component.getProductId() + ". Running product analysis.");
                    assignVulnerabilitiesToComponent(qm , component.getProductId(),component);
                } else {
                    LOGGER.info("Component " + component.getName() + " has a unique Product ID or no Product ID. Running normal analysis.");
                    versionRangeAnalysis(qm, component); // Run normal analysis
                }

            }
        }
    }

    private void versionRangeAnalysis(final QueryManager qm, final Component component) {

        LOGGER.info("Inside VersionRangeAnalysis Function");

        final boolean fuzzyEnabled = super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_ENABLED) &&
                (!component.isInternal() || !super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_EXCLUDE_INTERNAL));
        final boolean excludeComponentsWithPurl = super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_EXCLUDE_PURL);
        us.springett.parsers.cpe.Cpe parsedCpe = null;
        if (component.getCpe() != null) {
            try {
                parsedCpe = CpeParser.parse(component.getCpe());
            } catch (CpeParsingException e) {
                LOGGER.warn("An error occurred while parsing: " + component.getCpe() + " - The CPE is invalid and will be discarded. " + e.getMessage());
            }
        }
        List<VulnerableSoftware> vsList = Collections.emptyList();
        String componentVersion;
        if (parsedCpe != null) {
            componentVersion = parsedCpe.getVersion();
        } else if (component.getPurl() != null) {
            componentVersion = component.getPurl().getVersion();
        } else {
            // Catch cases where the CPE couldn't be parsed and no PURL exists.
            // Should be rare, but could lead to NPEs later.
            LOGGER.debug("Neither CPE nor PURL of component " + component.getUuid() + " provide a version - skipping analysis");
            return;
        }
        // In some cases, componentVersion may be null, such as when a Package URL does not have a version specified
        if (componentVersion == null) {
            return;
        }
        // https://github.com/DependencyTrack/dependency-track/issues/1574
        // Some ecosystems use the "v" version prefix (e.g. v1.2.3) for their components.
        // However, both the NVD and GHSA store versions without that prefix.
        // For this reason, the prefix is stripped before running analyzeVersionRange.
        //
        // REVISIT THIS WHEN ADDING NEW VULNERABILITY SOURCES!
        if (componentVersion.length() > 1 && componentVersion.startsWith("v")) {
            if (componentVersion.matches("v0.0.0-\\d{14}-[a-f0-9]{12}")) {
                componentVersion = componentVersion.substring(7,11) + "-" + componentVersion.substring(11,13) + "-" + componentVersion.substring(13,15);
            } else {
                componentVersion = componentVersion.substring(1);
            }
        }

        if (parsedCpe != null) {
            vsList = qm.getAllVulnerableSoftware(parsedCpe.getPart().getAbbreviation(), parsedCpe.getVendor(), parsedCpe.getProduct(), component.getPurl());
        } else {
            vsList = qm.getAllVulnerableSoftware(null, null, null, component.getPurl());
        }

        if (fuzzyEnabled && vsList.isEmpty()) {
            FuzzyVulnerableSoftwareSearchManager fm = new FuzzyVulnerableSoftwareSearchManager(excludeComponentsWithPurl);
            vsList = fm.fuzzyAnalysis(qm, component, parsedCpe);
        }
        super.analyzeVersionRange(qm, vsList, parsedCpe, componentVersion, component, vulnerabilityAnalysisLevel);
    }

    public void assignVulnerabilitiesToComponent(QueryManager qm, String productId, Component component) {
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
