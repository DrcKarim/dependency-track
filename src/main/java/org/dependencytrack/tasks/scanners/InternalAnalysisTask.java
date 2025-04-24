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
// import org.dependencytrack.model.Project;
// import org.dependencytrack.model.Vulnerability;
// import org.apache.commons.lang3.StringUtils;

// import java.util.Set;
// import java.util.HashSet;
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
                versionRangeAnalysis(qm, component);
           /*     if (component.getProductId() != null && qm.doesProductIdExist(component.getProductId()) ) {
                    LOGGER.info("Inside the filter");
                    LOGGER.info("Component " + component.getName() + " has a Product ID: " + component.getProductId() + ". Running product analysis.");
                    assignVulnerabilitiesToComponent(qm , component.getProductId(),component);
                } else {
                    LOGGER.info("Component " + component.getName() + " has a unique Product ID or no Product ID. Running normal analysis.");
                    versionRangeAnalysis(qm, component); // Run normal analysis
                } */

            }
        }
    }

 /* private void versionRangeAnalysis(final QueryManager qm, final Component component) {
        LOGGER.info("Inside VersionRangeAnalysis Function");

        // Analyze first CPE
        analyzeSingleCpe(qm, component, component.getCpe(), "CPE1");

        // Analyze second CPE
        analyzeSingleCpe(qm, component, component.getCpe2(), "CPE2");

        // Analyze combination: CPE1 + Running On/With CPE2
        analyzeCpeWithRunningOn(qm, component);
    }*/

    private void versionRangeAnalysis(final QueryManager qm, final Component component) {
        LOGGER.info("Inside VersionRangeAnalysis Function");

        final boolean hasCpe1 = component.getCpe() != null;
        final boolean hasCpe2 = component.getCpe2() != null;

        if (hasCpe1 && hasCpe2) {
            // Combined logic when both CPEs are defined
            analyzeCpeWithRunningOn(qm, component);
        } else if (hasCpe1) {
            // Fallback to individual analysis if only CPE1 is provided
            analyzeSingleCpe(qm, component, component.getCpe(), "CPE1");
        } else if (hasCpe2) {
            // Optional: analyze CPE2 alone
            analyzeSingleCpe(qm, component, component.getCpe2(), "CPE2");
        }
    }


    private void analyzeSingleCpe(final QueryManager qm, final Component component, final String cpe, final String label) {
        if (cpe == null && component.getPurl() == null) {
            LOGGER.debug(label + " is null and no PURL available for component " + component.getName());
            return;
        }

        final boolean fuzzyEnabled = super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_ENABLED)
                && (!component.isInternal() || !super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_EXCLUDE_INTERNAL));
        final boolean excludeComponentsWithPurl = super.isEnabled(ConfigPropertyConstants.SCANNER_INTERNAL_FUZZY_EXCLUDE_PURL);

        us.springett.parsers.cpe.Cpe parsedCpe = null;
        if (cpe != null) {
            try {
                parsedCpe = CpeParser.parse(cpe);
            } catch (CpeParsingException e) {
                LOGGER.warn("An error occurred while parsing " + label + ": " + cpe + " - It will be skipped. " + e.getMessage());
            }
        }

        List<VulnerableSoftware> vsList = Collections.emptyList();
        String componentVersion;

        if (parsedCpe != null) {
            componentVersion = parsedCpe.getVersion();
        } else if (component.getPurl() != null) {
            componentVersion = component.getPurl().getVersion();
        } else {
            LOGGER.debug("Neither " + label + " nor PURL of component " + component.getUuid() + " provide a version - skipping analysis");
            return;
        }

        if (componentVersion == null) {
            return;
        }

        // Normalize versions starting with 'v'
        if (componentVersion.length() > 1 && componentVersion.startsWith("v")) {
            if (componentVersion.matches("v0.0.0-\\d{14}-[a-f0-9]{12}")) {
                componentVersion = componentVersion.substring(7, 11) + "-" +
                        componentVersion.substring(11, 13) + "-" +
                        componentVersion.substring(13, 15);
            } else {
                componentVersion = componentVersion.substring(1);
            }
        }

        if (parsedCpe != null) {
            vsList = qm.getAllVulnerableSoftware(
                    parsedCpe.getPart().getAbbreviation(),
                    parsedCpe.getVendor(),
                    parsedCpe.getProduct(),
                    component.getPurl()
            );
        } else {
            vsList = qm.getAllVulnerableSoftware(null, null, null, component.getPurl());
        }

        if (fuzzyEnabled && vsList.isEmpty()) {
            FuzzyVulnerableSoftwareSearchManager fm = new FuzzyVulnerableSoftwareSearchManager(excludeComponentsWithPurl);
            vsList = fm.fuzzyAnalysis(qm, component, parsedCpe);
        }

        super.analyzeVersionRange(qm, vsList, parsedCpe, componentVersion, component, vulnerabilityAnalysisLevel);
    }



    private void analyzeCpeWithRunningOn(final QueryManager qm, final Component component) {
        LOGGER.info("Analyzing CPE1 + Running On (CPE2)");
        final String cpe1 = component.getCpe();
        final String cpe2 = component.getCpe2();
        if (cpe1 == null || cpe2 == null) {
            LOGGER.info("Both CPE1 and CPE2 must be provided for running-with analysis.");
            return;
        }
        try {
            us.springett.parsers.cpe.Cpe parsedCpe1 = CpeParser.parse(cpe1);
            us.springett.parsers.cpe.Cpe parsedCpe2 = CpeParser.parse(cpe2);

            String part1 = parsedCpe1.getPart().getAbbreviation(); // usually "a"
            String vendor1 = parsedCpe1.getVendor();
            String product1 = parsedCpe1.getProduct();
            String version1 = parsedCpe1.getVersion();

            String product2 = parsedCpe2.getProduct();
            //  Fetch vulnerable software matching CPE1 (main match)
            List<VulnerableSoftware> allCpe1Matches = qm.getAllVulnerableSoftware(part1, vendor1, product1, component.getPurl());
            // Filter by targetSw or targetHw containing CPE2's product
            List<VulnerableSoftware> matchedVulnSoftware = allCpe1Matches.stream()
                    .filter(vs -> {
                        String targetSw = vs.getTargetSw();
                        String targetHw = vs.getTargetHw();
                        return (targetSw != null && targetSw.toLowerCase().contains(product2.toLowerCase())) ||
                                (targetHw != null && targetHw.toLowerCase().contains(product2.toLowerCase()));
                    })
                    .toList();
            if (matchedVulnSoftware.isEmpty()) {
                LOGGER.info("No vulnerabilities matched for CPE1 + Running On/With CPE2.");
            }

            // Reuse existing logic
            super.analyzeVersionRange(qm, matchedVulnSoftware, parsedCpe1, version1, component, vulnerabilityAnalysisLevel);

        } catch (CpeParsingException e) {
            LOGGER.warn("Invalid CPEs provided. Skipping: " + e.getMessage());
        }
    }

}
