/*
 * Copyright (C) 2021 Sonatype, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * License-Filename: LICENSE
 */

package org.ossreviewtoolkit.advisor.advisors

import java.io.IOException
import java.time.Instant

import org.ossreviewtoolkit.advisor.AbstractVulnerabilityProviderFactory
import org.ossreviewtoolkit.advisor.VulnerabilityProvider
import org.ossreviewtoolkit.clients.ossindex.OssIndexService
import org.ossreviewtoolkit.model.AdvisorDetails
import org.ossreviewtoolkit.model.AdvisorResult
import org.ossreviewtoolkit.model.AdvisorSummary
import org.ossreviewtoolkit.model.Package
import org.ossreviewtoolkit.model.Vulnerability
import org.ossreviewtoolkit.model.VulnerabilityReference
import org.ossreviewtoolkit.model.config.AdvisorConfiguration
import org.ossreviewtoolkit.model.utils.PurlType
import org.ossreviewtoolkit.model.utils.getPurlType
import org.ossreviewtoolkit.model.utils.toPurl
import org.ossreviewtoolkit.utils.log

import retrofit2.HttpException
import java.net.URI

/**
 * The number of packages to request from Sonatype OSS Index in one request.
 */
private const val REQUEST_CHUNK_SIZE = 128

/**
 * A wrapper for [Sonatype OSS Index](https://ossindex.sonatype.org/) security vulnerability data.
 */
class OssIndex(name: String) : VulnerabilityProvider(name) {
    class Factory : AbstractVulnerabilityProviderFactory<OssIndex>("OssIndex") {
        override fun create(config: AdvisorConfiguration) = OssIndex(providerName)
    }

    override suspend fun retrievePackageVulnerabilities(packages: List<Package>): Map<Package, List<AdvisorResult>> {
        val startTime = Instant.now()

        val components = packages.map { pkg ->
            val packageUrl = buildString {
                append(pkg.purl)

                when (pkg.id.getPurlType()) {
                    PurlType.MAVEN.toString() -> append("?type=jar")
                    PurlType.PYPI.toString() -> append("?extension=tar.gz")
                }
            }

            packageUrl
        }

        return try {
            val componentDetails = mutableMapOf<String, OssIndexService.Component>()

            components.chunked(REQUEST_CHUNK_SIZE).forEach { chunk ->
                val requestResults = getComponentReport(service, chunk).componentDetails.associateBy {
                    it.component.packageUrl.substringBefore("?")
                }

                componentDetails += requestResults.filterValues { it.securityData.securityIssues.isNotEmpty() }
            }

            val endTime = Instant.now()

            packages.mapNotNullTo(mutableListOf()) { pkg ->
                componentDetails[pkg.id.toPurl()]?.let { details ->
                    pkg to listOf(
                        AdvisorResult(
                            details.securityData.securityIssues.mapNotNull { it.toVulnerability() },
                            AdvisorDetails(providerName),
                            AdvisorSummary(startTime, endTime)
                        )
                    )
                }
            }.toMap()
        } catch (e: IOException) {
            createFailedResults(startTime, packages, e)
        }
    }

    /**
     * Construct a [Vulnerability] from the data stored in this issue. As a [VulnerabilityReference] requires a
     * non-null URI, issues without an URI yield *null* results. (This is rather a paranoia check, as issues are
     * expected to have a URI.)
     */
    private fun OssIndexService.SecurityIssue.toVulnerability(): Vulnerability? {
        val references = mutableListOf<VulnerabilityReference>()

        val browseUrl = URI("${nexusIqConfig.browseUrl}/assets/index.html#/vulnerabilities/$reference")
        val nexusIqReference = VulnerabilityReference(browseUrl, scoringSystem(), severity.toString())

        references += nexusIqReference
        url.takeIf { it != browseUrl }?.let { references += nexusIqReference.copy(url = it) }

        return Vulnerability(reference, references)
    }

    /**
     * Invoke the [NexusIQ service][service] to request detail information for the given [components]. Catch HTTP
     * exceptions thrown by the service and re-throw them as [IOException].
     */
    private suspend fun getComponentReport(
        service: OssIndexService,
        components: List<OssIndexService.Component>
    ): NexusIqService.ComponentDetailsWrapper =
        try {
            log.debug { "Querying component details from ${nexusIqConfig.serverUrl}." }
            service.getComponentReport(OssIndexService.ComponentsRequest(components))
        } catch (e: HttpException) {
            throw IOException(e)
        }
}
