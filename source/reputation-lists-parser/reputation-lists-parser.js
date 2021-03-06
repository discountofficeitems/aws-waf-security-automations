/*******************************************************************************
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved. 
 *
 * Licensed under the Amazon Software License (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0    
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 ********************************************************************************/

const readline = require('readline');
const aws = require('aws-sdk');
const https = require('https');

// configure API retries
aws.config.update({
    maxRetries: 5,
    retryDelayOptions: {
        base: 1000
    }
});
const waf = new aws.WAFV2();
const cloudwatch = new aws.CloudWatch();

/**
 * Maximum number of IP descriptors per IP Set
 */
const maxDescriptorsPerIpSet = 10000;

/**
 * Convert a dotted-decimal formated address to an integer
 */
function dottedToNumber(dotted) {
    const splitted = dotted.split('.');
    return (((((Number(splitted[0]) * 256) + Number(splitted[1])) * 256) + Number(splitted[2])) * 256) + Number(splitted[3]);
}

/**
 * Convert an IPv4 address integer to dotted-decimal format
 */
function numberToDotted(number) {
    var dotted = String(number % 256);
    for (var j = 3; j > 0; j--) {
        number = Math.floor(number / 256);
        dotted = String(number % 256) + '.' + dotted;
    }
    return dotted;
}

class Range {
    /**
     * Constructs a new object representing an IPv4 address range
     * @class
     * @classdesc An IPv4 address range
     * @param {List} list - The List object that the range is defined in
     * @param {string|number} address - Either a number, a dotted decimal address, or a CIDR
     * @param {number} [mask] - The mask, ignored if address is CIDR
     */
    constructor(list, address, mask) {
        this.list = list;
        // check to see if the address is in dotted-decimal format, optionally including the mask
        if ((typeof address == 'string') && (address.indexOf('.') !== -1)) {
            const slashPosition = address.indexOf('/');
            if (slashPosition === -1) {
                this.dotted = address;
                this.mask = 32;
            } else {
                this.dotted = address.substring(0, slashPosition);
                this.mask = Number(address.substring(slashPosition + 1));
            }
            this.number = dottedToNumber(this.dotted);
        } else {
            this.number = Number(address);
            this.mask = mask || 32;
            this.dotted = numberToDotted(this.number);
        }
        this.cidr = this.dotted + '/' + this.mask;
        this.lastNumber = this.number + Math.pow(2, 32 - this.mask);
    }

    /**
     * Test if the other range is contained within this one
     * @param {Range} other - The other range
     */
    contains(other) {
        return ((this.number <= other.number) && (this.lastNumber >= other.lastNumber));
    }

    toString() {
        return this.cidr;
    }
}

class List {
    /**
     * Constructs a new object containing an URL to a reputation list
     * @class
     * @classdesc An IP Reputation List
     * @param {string} url - URL to the reputation list
     * @param {string} prefix - Regular Expression prefix before the IP address
     */
    constructor(url, prefix = '') {
        this.url = url;
        this.prefix = prefix;
        // Fix for github issue #40
        // a regular expression to find the address or range on each line of the list, with an option prefix before it
        this.regex = new RegExp('^' + this.prefix + '\\s*((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])(?:/(?:3[0-2]|[1-2][0-9]|[0-9]))?)');
    }

    getRanges() {
        return new Promise((resolve, reject) => {
            const ranges = [];
            https.get(this.url, (response) => {
                const reader = readline.createInterface({
                    terminal: false,
                    input: response,
                });

                reader.on('line', (line) => {
                    const result = this.regex.exec(line);
                    // if there is a result, a range has been found and a new range is created
                    if (result) {
                        ranges.push(new Range(this, result[1]));
                    }
                });

                reader.on('close', () => {
                    console.log(ranges.length + ' address ranges read from ' + this.url);
                    resolve(ranges);
                });
            }).on('error', (err) => {
                reject(err);
            });
        });
    }

    equals(other) {
        return this.url === other.url;
    }

    toString() {
        return this.url;
    }
}

/**
 * Logs an array of ranges, with optional message, to console
 * @param {Range[]} ranges - List of ranges
 * @param {string} [message] - Message
 */
function logRanges(ranges, message) {
    if (message) {
        console.log(ranges.length + ' ranges ' + message);
    }
}

/**
 * Sorts an array of ranges by largest first
 * @param {Range[]} ranges - List of ranges
 */
function prioritizeRanges(ranges) {
    ranges.sort(function (a, b) {
        return a.mask - b.mask;
    });
    logRanges(ranges, 'after prioritzing');
}

/**
 * Removes ranges from a list if they are contained within other ranges
 * @param {Range[]} ranges - List of ranges
 */
function removeContainedRanges(ranges) {
    for (let i = 0; i < ranges.length; i++) {
        const range = ranges[i];
        for (let j = 0; j < ranges.length; j++) {
            const other = ranges[j];
            if (range.contains(other) && (j !== i)) {
                ranges.splice(j, 1);
                if (j < i) {
                    i--;
                }
                j--;
            }
        }
    }
    logRanges(ranges, 'after removing contained ones');
}

/**
 * Combine ranges into larger /8, /16 through /31 ranges
 * @param {Range[]} ranges - Array of ranges
 */
function CombineRanges(ranges) {
    // TODO: should check if we can combine ranges into a larger /8, /16 through /31 ranges
}

/**
 * Split ranges into smaller /8 or /16 ranges
 * @param {Range[]} ranges - Array of ranges
 */
function splitRanges(ranges) {
    // AWS WAF only supports ranges with /8 or /16 through /32 ranges
    // Therefore, split ranges into ones that have the above masks
    // For example = /7 can be decomposed into 2 /8 ranges, /9 can be decomposed into 128 /16 ranges
    for (let i = 0; i < ranges.length; i++) {
        const range = ranges[i];
        const list = range.list;
        const mask = range.mask;
        const supportedMask = (mask <= 8 ? 8 : mask <= 16 ? 16 : mask);
        const supportedMaskDifference = supportedMask - mask;
        // Check if the mask is not a /8, /16 through /32
        if (supportedMaskDifference > 0) {
            const size = Math.pow(2, 32 - supportedMask);
            const count = Math.pow(2, supportedMaskDifference);
            const newRanges = [];
            // create new ranges that have /8, /16 through /32 masks to replace this
            for (let j = 0; j < count; j++) {
                newRanges.push(new Range(list, range.number + (j * size), supportedMask));
            }
            // Insert the new ranges into the array, removing this one
            Array.prototype.splice.apply(ranges, [i, 1].concat(newRanges));
            // move the pointer to after the newly-inserted ranges
            i += newRanges.length - 1;
        }
    }
    logRanges(ranges, 'after splitting to /8, /16 through /32 ranges...');
}

/**
 * Flattens an array of arrays into an array
 * @param {Array[]} arr - Array of arrays
 */
function flattenArrayArray(arr) {
    return arr.reduce(function (a, b) {
        return a.concat(b);
    }, []);
}

/**
 * Flattens an array of objects into an array
 * @param {object[]} arr - Array of objects
 * @param {string} propertyName - Name of property of array elements to extract
 */
function flattenObjectArray(arr, propertyName) {
    return arr.map(function (o) {
        return o[propertyName];
    });
}

function getReputationIpSetSize(ipSets) {
    let reputationIpSetSize = 0;
    for (const ipSet of ipSets) {
        reputationIpSetSize += ipSet.Addresses.length;
    }

    return reputationIpSetSize;
}

async function getCloudWatchDataPointSum(metricName) {
    const endTime = new Date();
    let startTime = new Date();
    startTime = new Date(startTime.setHours(startTime.getHours() - 12));

    const { Datapoints: dataPoints } = await cloudwatch.getMetricStatistics({
        EndTime: endTime,
        MetricName: metricName,
        Namespace: 'WAF',
        Period: 12 * 3600,
        StartTime: startTime,
        Statistics: ['Sum'],
        Dimensions: [{
            Name: "Rule",
            Value: "ALL"
        }, {
            Name: "WebACL",
            Value: process.env.ACL_METRIC_NAME + 'MaliciousRequesters'
        }]
    }).promise();

    let allowedRequests = 0;
    for (const dataPoint of dataPoints) {
        allowedRequests += dataPoint.Sum;
    }

    return allowedRequests;
}

/**
 * Sends anonymous data to AWS (if SendAnonymousUsageData CloudFormation parameter is set to yes).
 * @param {object[]} ipSets - array of IpSets
 */
async function send_anonymous_usage_data(ipSets) {
    if (process.env.SEND_ANONYMOUS_USAGE_DATA.toLowerCase() !== "yes") {
        return 'Data sent';
    }

    const [
        reputationIpSetSize,
        allowedRequests,
        blockedRequests,
        blockedRequestsIpReputationLists,
    ] = await Promise.all([
        getReputationIpSetSize(ipSets),
        getCloudWatchDataPointSum('AllowedRequests'),
        getCloudWatchDataPointSum('BlockedRequests'),
        getCloudWatchDataPointSum(process.env.ACL_METRIC_NAME + 'IPReputationListsRule'),
    ]);

    const requestBody = JSON.stringify({
        "Solution": "SO0006",
        "UUID": process.env.UUID,
        "TimeStamp": new Date(),
        "Data": {
            "Version": "2",
            "data_type": "reputation_list",
            "ip_reputation_lists_size": reputationIpSetSize,
            "allowed_requests": allowedRequests,
            "blocked_requests_all": blockedRequests,
            "blocked_requests_ip_reputation_lists": blockedRequestsIpReputationLists,
            "waf_type": process.env.ENDPOINT_TYPE
        }
    });

    console.info('[send_anonymous_usage_data] Send Data');

    const req = https.request({
        host: 'metrics.awssolutionsbuilder.com',
        port: '443',
        path: '/generic',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(requestBody)
        }
    }, (response) => {
        response.setEncoding('utf8');
        response.on('error', (err) => {
            console.debug('[send_anonymous_usage_data] Problem with request: ' + err.message);
        });
        response.on('end', () => {
            console.debug('[send_anonymous_usage_data] Request created: ' + requestBody);
        });
    });

    req.on('error', (err) => {
        console.debug('[send_anonymous_usage_data] Problem with request: ' + err.message);
    });

    req.write(requestBody);
    req.end();

    console.info('Data sent');
}

/**
 * Main handler
 */
exports.handler = async (event) => {
    console.log('[handler] event: ' + JSON.stringify(event));
    if (!event || !event.lists || !event.lists.length || !event.ipSetRefs || !event.ipSetRefs.length) {
        return 'Nothing to do';
    }

    const [
        rangesForEachList,
        allIpSets,
    ] = await Promise.all([
        Promise.all(event.lists.map((list) => {
            const request = new List(list.url, list.prefix);
            return request.getRanges();
        })),
        Promise.all(event.ipSetRefs.map((ipSetRef) => {
            const reference = ipSetRef.split('|');
            return waf.getIPSet({
                Name: reference[0],
                Id: reference[1],
                Scope: reference[2],
            }).promise().then((response) => {
                // Move a few details into the "IPSet"
                // This is not really the proper way, but limits further
                // refactoring in switching to WAFv2
                response.IPSet.Scope = reference[2];
                response.IPSet.LockToken = response.LockToken;

                return response;
            });
        })),
    ]);
    const ranges = flattenArrayArray(rangesForEachList);
    console.log('[handler] ' + ranges.length + ' ranges in total');
    removeContainedRanges(ranges);
    CombineRanges(ranges);
    splitRanges(ranges);
    prioritizeRanges(ranges);

    const ipSets = flattenObjectArray(allIpSets, 'IPSet');
    console.log('[handler] ' + ipSets.length + ' IP Sets in total');

    for (const [index, ipSet] of ipSets.entries()) {
        const addresses = ipSet.Addresses;
        const begin = index * maxDescriptorsPerIpSet;
        const rangeSlice = flattenObjectArray(ranges.slice(begin, begin + maxDescriptorsPerIpSet), 'cidr');

        if (addresses.length === rangeSlice.length && addresses.sort().equals(rangeSlice.sort())) {
            console.log('[handler] No update required for IP set' + ipSet.Name);
            continue;
        }

        console.log('[handler] IP Set ' + ipSet.Name + ' has ' + addresses.length + ' addresses and should have ' + rangeSlice.length);

        await waf.updateIPSet({
            LockToken: ipSet.LockToken,
            Id: ipSet.Id,
            Name: ipSet.Name,
            Scope: ipSet.Scope,
            Addresses: rangeSlice,
        }).promise().then((response) => {
            ipSet.Addresses = rangeSlice;
            ipSet.LockToken = response.NextLockToken;
        });
    }

    await send_anonymous_usage_data(ipSets);
};
