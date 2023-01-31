package burp.Replacements;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.Utils.Utils;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class Replacement {
    public static final String[] REPLACEMENT_TYPE_OPTIONS = {
            "Request String",

            "Request Header",
            "Request Body",
            "Request Param Name",
            "Request Param Value",
            "Request Cookie Name",
            "Request Cookie Value",
            "Request First Line",

            "Add Header",

            "Remove Parameter By Name",
            "Remove Parameter By Value",
            "Remove Cookie By Name",
            "Remove Cookie By Value",
            "Remove Header By Name",
            "Remove Header By Value",

            "Match Param Name, Replace Value",
            "Match Cookie Name, Replace Value",
            "Match Header Name, Replace Value"
            //"Remove Header By Name",
            //"Remove Header By Value"
    };

    enum ReplacementCountOption {

        REPLACE_FIRST("Replace First"),
        REPLACE_ALL("Replace All"),
        REPLACE_ALL_POSSIBILITIES("Replace all possibilities");

        final String value;

        ReplacementCountOption(String value) {
            this.value = value;
        }

        public static String valueOf(ReplacementCountOption option) {
            return option.value;
        }

        public static ReplacementCountOption byValue(String value) {
            if (value == null)
                return null;
            for (ReplacementCountOption option : ReplacementCountOption.values()) {
                if (option.value.equals(value))
                    return option;
            }
            return null;
        }

        public static String[] stringValues() {
            return Arrays.stream(ReplacementCountOption.values()).map(o -> o.value).toArray(String[]::new);
        }
    }

    private enum MatchAndReplaceType {
        MATCH_NAME_REPLACE_NAME,
        MATCH_NAME_REPLACE_VALUE,
        MATCH_VALUE_REPLACE_VALUE,
        MATCH_VALUE_REPLACE_NAME,
        MATCH_NAME_REMOVE,
        MATCH_VALUE_REMOVE
    }

    private String type;
    private String match;
    private String replace;
    private String comment;
    private ReplacementCountOption which;

    private Boolean isRegexMatch;
    private Boolean isEnabled;

    public Replacement(
            String type,
            String match,
            String replace,
            String which,
            String comment,
            boolean isRegexMatch) {
        this.type = type;
        this.match = match;
        this.replace = replace;
        this.which = ReplacementCountOption.byValue(which);
        this.comment = comment;
        this.isRegexMatch = isRegexMatch;
        this.isEnabled = true;
    }

    public Replacement(
            String type,
            String match,
            String replace,
            String which,
            String comment,
            boolean isRegexMatch,
            boolean isEnabled) {
        this(type, match, replace, which, comment, isRegexMatch);
        this.setEnabled(isEnabled);
    }

    public Replacement(Replacement replacement) {
        this(replacement.getType(),
                replacement.getMatch(),
                replacement.getReplace(),
                replacement.getWhich(),
                replacement.getComment(),
                replacement.isRegexMatch(),
                replacement.isEnabled());
    }

    private List<byte[]> updateBurpParam(
            byte[] request,
            int parameterType,
            MatchAndReplaceType matchAndReplaceType) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        // Need to only use params that can be added or removed.
        List<IParameter> parameters = analyzedRequest.getParameters().stream()
                .filter(p -> p.getType() == parameterType)
                .collect(Collectors.toList());
        List<IParameter> originalParameters = new ArrayList<>(parameters.size());
        Collections.copy(originalParameters, parameters);

        //for (IParameter param : originalParameters) {
        //  BurpExtender.getCallbacks().printOutput(param.getName());
        //}
        //BurpExtender.getCallbacks().printOutput("-----");
        //for (IParameter param : parameters) {
        //  BurpExtender.getCallbacks().printOutput(param.getName());
        //}


        if (ReplacementCountOption.REPLACE_FIRST == which || ReplacementCountOption.REPLACE_ALL == which) {
            boolean wasChanged = false;

            for (ListIterator<IParameter> iterator = parameters.listIterator(); iterator.hasNext(); ) {
                int i = iterator.nextIndex();
                IParameter currentParameter = iterator.next();
                //BurpExtender.getCallbacks().printOutput(currentParameter.getName());
                //BurpExtender.getCallbacks().printOutput(currentParameter.getValue());
                if (parameterMatches(currentParameter, matchAndReplaceType)) {
                    replaceParameter(iterator, currentParameter, matchAndReplaceType, i, parameters, helpers);
                    wasChanged = true;
                }
                // Bail if anything was changed
                if (ReplacementCountOption.REPLACE_FIRST == which) {
                    if (wasChanged) {
                        break;
                    }
                }
            }
            if (wasChanged) {
                return Collections.singletonList(rebuildRequestParams(request, helpers, parameters, originalParameters));
            }
        } else {
            List<List<IParameter>> paramLists = new ArrayList<>();
            replaceParamsRecursive(paramLists, parameters, 0, matchAndReplaceType, helpers);
            if (paramLists.isEmpty())
                paramLists.add(parameters);
            return paramLists.stream().map(p -> rebuildRequestParams(request, helpers, p, originalParameters)).collect(Collectors.toList());

        }
        // Return the modified request
        return Collections.singletonList(request);
    }

    private byte[] rebuildRequestParams(byte[] request, IExtensionHelpers helpers, List<IParameter> parameters, List<IParameter> originalParameters) {
        byte[] tempRequest = Arrays.copyOf(request, request.length);
        // Remove every parameter
        for (IParameter param : originalParameters) {
            tempRequest = helpers.removeParameter(tempRequest, param);
        }
        // Add them back
        for (IParameter param : parameters) {
            tempRequest = helpers.addParameter(tempRequest, param);
        }
        // Update the body and headers
        IRequestInfo tempAnalyzedRequest = helpers.analyzeRequest(tempRequest);
        byte[] body = Arrays
                .copyOfRange(tempRequest, tempAnalyzedRequest.getBodyOffset(), tempRequest.length);
        List<String> headers = tempAnalyzedRequest.getHeaders();
        return helpers.buildHttpMessage(headers, body);
    }

    private boolean parameterMatches(IParameter parameter, MatchAndReplaceType matchAndReplaceType) {
        switch (matchAndReplaceType) {
            case MATCH_NAME_REPLACE_NAME:
            case MATCH_NAME_REPLACE_VALUE:
            case MATCH_NAME_REMOVE:
                return matches(parameter.getName());
            case MATCH_VALUE_REPLACE_VALUE:
            case MATCH_VALUE_REPLACE_NAME:
            case MATCH_VALUE_REMOVE:
                return matches(parameter.getValue());
            default:
                return false;
        }
    }

    private void replaceParameter(ListIterator<IParameter> iterator, IParameter parameter, MatchAndReplaceType matchAndReplaceType, int i,
                                  List<IParameter> parameters, IExtensionHelpers helpers) {
        switch (matchAndReplaceType) {
            case MATCH_NAME_REPLACE_NAME:
            case MATCH_VALUE_REPLACE_NAME:
                // Each if statement checks whether isRegexMatch && check regex
                // || regular string compare
                parameters.set(i, helpers.buildParameter(
                        this.replace,
                        parameter.getValue(),
                        parameter.getType()));
                break;
            case MATCH_NAME_REPLACE_VALUE:
            case MATCH_VALUE_REPLACE_VALUE:
                parameters.set(i, helpers.buildParameter(
                        parameter.getName(),
                        this.replace,
                        parameter.getType()));
                break;
            case MATCH_NAME_REMOVE:
            case MATCH_VALUE_REMOVE:
                if (iterator != null)
                    iterator.remove();
                else parameters.remove(i);
                break;
            default:
                break;
        }
    }


    private void replaceParamsRecursive(List<List<IParameter>> paramLists, List<IParameter> original, int index, MatchAndReplaceType matchAndReplaceType, IExtensionHelpers helpers) {
        if (index > original.size())
            return;

        int count = 1;
        for (int i = index; i < original.size(); i++) {
            IParameter currentParameter = original.get(i);
            if (parameterMatches(currentParameter, matchAndReplaceType)) {
                List<IParameter> newList = new ArrayList<>(original.size());
                Collections.copy(newList, original);

                if (count == 1) {
                    replaceParameter(null, currentParameter, matchAndReplaceType, i + 1, newList, helpers);
                    paramLists.add(newList);
                    replaceParamsRecursive(paramLists, newList, i + 1, matchAndReplaceType, helpers);
                } else if (count == 2) {
                    replaceParamsRecursive(paramLists, original, i + 1, matchAndReplaceType, helpers);
                } else replaceParamsRecursive(paramLists, newList, i, matchAndReplaceType, helpers);
                count++;
            }
        }
    }


    // This is a hack around binary content causing requests to send
    private List<byte[]> updateContent(byte[] request) {
        switch (which) {
            case REPLACE_FIRST:
                return Collections.singletonList(Utils.byteArrayRegexReplaceFirst(request, this.match, this.replace));
            case REPLACE_ALL:
                return Collections.singletonList(Utils.byteArrayRegexReplaceAll(request, this.match, this.replace));
            case REPLACE_ALL_POSSIBILITIES:
                return Utils.byteArrayRegexReplaceAllPossibilities(request, this.match, this.replace);
        }
        return null;
    }


    private List<byte[]> updateHeader(byte[] request) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        List<String> headers = analyzedRequest.getHeaders();
        byte[] body = Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length);
        headers = headers.stream().filter(h -> h != null && !h.isEmpty()).collect(Collectors.toList());

        switch (which) {
            case REPLACE_FIRST:
                String header = headers.stream().filter(this::matches).findFirst().orElse(null);
                if (header != null) {
                    int index = headers.indexOf(header);
                    if (index >= 0) {
                        headers.set(index, this.replace);
                    }
                }
                break;
            case REPLACE_ALL:
                headers = headers.stream().map(h -> matches(h) ? this.replace : h).collect(Collectors.toList());
                break;
            case REPLACE_ALL_POSSIBILITIES:
                List<List<String>> headersLists = new ArrayList<>();
                replaceHeadersRecursive(headersLists, headers, 0, this::matches, (h) -> h);
                if (headersLists.isEmpty()) {
                    headersLists.add(headers);
                }
                return headersLists.stream().map(l -> helpers.buildHttpMessage(l, body)).collect(Collectors.toList());
        }

        return Collections.singletonList(helpers.buildHttpMessage(headers, body));
    }

    private void replaceHeadersRecursive(List<List<String>> headersLists, List<String> original, int index, Function<String, Boolean> matchingFunc, Function<String, String> operation) {
        if (index >= original.size())
            return;
        int count = 1;
        for (int i = index; i < original.size(); i++) {
            String h = original.get(i);
            if (matchingFunc.apply(h)) {
                List<String> newList = new ArrayList<>(original.size());
                Collections.copy(newList, original);

                if (count == 1) {
                    newList.set(i, operation.apply(h));
                    headersLists.add(newList);
                    replaceHeadersRecursive(headersLists, newList, i + 1, matchingFunc, operation);
                } else if (count == 2) {
                    replaceHeadersRecursive(headersLists, original, i + 1, matchingFunc, operation);
                } else replaceHeadersRecursive(headersLists, newList, i, matchingFunc, operation);
                count++;
            }
        }
    }

    private boolean matches(String value) {
        return this.isRegexMatch && value.matches(this.match) || value.equals(this.match);
    }

    private List<byte[]> addHeader(byte[] request) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        List<String> headers = analyzedRequest.getHeaders();
        // Strip content-length to make sure it's the last param
        if (headers.get(headers.size() - 1).startsWith("Content-Length:")) {
            headers.remove(headers.size() - 1);
        }
        byte[] body = Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length);
        headers.add(this.replace);
        return Collections.singletonList(helpers.buildHttpMessage(headers, body));
    }

    private List<byte[]> matchHeaderNameUpdateValue(byte[] request) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        List<String> headers = analyzedRequest.getHeaders();
        byte[] body = Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length);
        headers = headers.stream().filter(h -> h != null && !h.isEmpty()).collect(Collectors.toList());

        switch (which) {
            case REPLACE_FIRST:
                String header = headers.stream().
                        map(h -> h.split(":", 2)).
                        filter(split -> split.length == 2)
                        .filter(split -> matches(split[0])).findFirst()
                        .map(split -> split[0] + ": " + this.replace).orElse(null);
                if (header != null) {
                    int index = headers.indexOf(header);
                    if (index >= 0) {
                        headers.set(index, this.replace);
                    }
                }
                break;
            case REPLACE_ALL:
                headers = headers.stream().map(h -> {
                    String[] split = h.split(":", 2);
                    if (split.length == 2 && matches(split[0])) {
                        return split[0] + ": " + this.replace;
                    } else return h;
                }).collect(Collectors.toList());
                break;
            case REPLACE_ALL_POSSIBILITIES:
                List<List<String>> headersLists = new ArrayList<>();
                replaceHeadersRecursive(headersLists, headers, 0, (h) -> {
                    String[] split = h.split(":", 2);
                    if (split.length == 2) {
                        return matches(split[0]);
                    } else return false;
                }, (h) -> {
                    String[] split = h.split(":", 2);
                    if (split.length == 2) {
                        return split[0] + ": " + this.replace;
                    } else return h;
                });
                if (headersLists.isEmpty()) {
                    headersLists.add(headers);
                }
                return headersLists.stream().map(l -> helpers.buildHttpMessage(l, body)).collect(Collectors.toList());
        }

        return Collections.singletonList(helpers.buildHttpMessage(headers, body));

    }

    private byte[] updateRequestBody(byte[] request) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        List<String> headers = analyzedRequest.getHeaders();
        byte[] body = Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length);
        boolean wasChanged = false;
        String bodyString;

        bodyString = new String(body, StandardCharsets.UTF_8);

        if (this.isRegexMatch) {
            if (bodyString.matches(this.match)) {
                body = this.replace.getBytes();
                wasChanged = true;
            }
        } else {
            if (bodyString.equals(this.match)) {
                body = bodyString.replace(this.match, this.replace).getBytes();
                wasChanged = true;
            }
        }
        // This helps deal with binary data getting messed up from the string conversion and causing a new request.
        if (wasChanged) {
            return helpers.buildHttpMessage(headers, body);
        } else {
            return request;
        }
    }

    private List<byte[]> updateRequestParamName(byte[] request) {
        if (!Utils.isRequestMultipartForm(request)) {
            return updateBurpParam(request, IParameter.PARAM_BODY,
                    MatchAndReplaceType.MATCH_NAME_REPLACE_NAME).stream().flatMap(
                    r -> updateBurpParam(r, IParameter.PARAM_URL,
                            MatchAndReplaceType.MATCH_NAME_REPLACE_NAME).stream()
            ).collect(Collectors.toList());
        } else {
            return Collections.singletonList(request);
        }
    }

    private List<byte[]> updateRequestParamValue(byte[] request) {
        if (!Utils.isRequestMultipartForm(request)) {
            return updateBurpParam(request, IParameter.PARAM_BODY,
                    MatchAndReplaceType.MATCH_VALUE_REPLACE_VALUE).stream().flatMap(
                    r -> updateBurpParam(r, IParameter.PARAM_URL,
                            MatchAndReplaceType.MATCH_VALUE_REPLACE_VALUE).stream()
            ).collect(Collectors.toList());
        } else {
            return Collections.singletonList(request);
        }
    }

    private List<byte[]> updateRequestParamValueByName(byte[] request) {
        if (!Utils.isRequestMultipartForm(request)) {
            return updateBurpParam(request, IParameter.PARAM_BODY,
                    MatchAndReplaceType.MATCH_NAME_REPLACE_VALUE).stream().flatMap(
                    r -> updateBurpParam(r, IParameter.PARAM_URL,
                            MatchAndReplaceType.MATCH_NAME_REPLACE_VALUE).stream()
            ).collect(Collectors.toList());
        } else {
            return Collections.singletonList(request);
        }
    }

    private List<byte[]> updateCookieName(byte[] request) {
        return updateBurpParam(request, IParameter.PARAM_COOKIE,
                MatchAndReplaceType.MATCH_NAME_REPLACE_NAME);
    }

    private List<byte[]> updateCookieValue(byte[] request) {
        return updateBurpParam(request, IParameter.PARAM_COOKIE,
                MatchAndReplaceType.MATCH_VALUE_REPLACE_VALUE);
    }

    private List<byte[]> removeParameterByName(byte[] request) {
        if (!Utils.isRequestMultipartForm(request)) {
            return updateBurpParam(request, IParameter.PARAM_BODY,
                    MatchAndReplaceType.MATCH_NAME_REMOVE).stream().flatMap(
                    r -> updateBurpParam(r, IParameter.PARAM_URL,
                            MatchAndReplaceType.MATCH_NAME_REMOVE).stream()
            ).collect(Collectors.toList());
        } else {
            return Collections.singletonList(request);
        }
    }

    private List<byte[]> removeParameterByValue(byte[] request) {
        if (Utils.isRequestMultipartForm(request)) {
            return updateBurpParam(request, IParameter.PARAM_BODY,
                    MatchAndReplaceType.MATCH_VALUE_REMOVE).stream().flatMap(
                    r -> updateBurpParam(r, IParameter.PARAM_URL,
                            MatchAndReplaceType.MATCH_VALUE_REMOVE).stream()
            ).collect(Collectors.toList());
        } else {
            return Collections.singletonList(request);
        }
    }

    private List<byte[]> removeCookieByName(byte[] request) {
        return updateBurpParam(request, IParameter.PARAM_COOKIE,
                MatchAndReplaceType.MATCH_NAME_REMOVE);
    }

    private List<byte[]> removeCookieByValue(byte[] request) {
        return updateBurpParam(request, IParameter.PARAM_COOKIE,
                MatchAndReplaceType.MATCH_VALUE_REMOVE);
    }

    private List<byte[]> removeHeaderByName(byte[] request) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        byte[] body = Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length);
        List<String> headers = new ArrayList<>();

        switch (which) {
            case REPLACE_FIRST:
                AtomicInteger index = new AtomicInteger(0);
                headers = analyzedRequest.getHeaders().stream().filter(h -> !(matches(h.split(":")[0]) &&
                        index.getAndIncrement() < 1)).collect(Collectors.toList());
                break;
            case REPLACE_ALL:
                headers = analyzedRequest.getHeaders().stream()
                        .filter(h -> !(matches(h.split(":")[0]))).collect(Collectors.toList());
                break;
            case REPLACE_ALL_POSSIBILITIES:
                List<List<String>> headersLists = new ArrayList<>();
                for (ListIterator<String> it = analyzedRequest.getHeaders().listIterator(); it.hasNext(); ) {
                    String header = it.next();
                    if (matches(header.split(":")[0])) {
                        it.remove();
                        List<String> newList = new ArrayList<>(analyzedRequest.getHeaders().size());
                        Collections.copy(newList, analyzedRequest.getHeaders());
                        headersLists.add(newList);
                    }
                }
                if (headersLists.isEmpty()) headersLists.add(analyzedRequest.getHeaders());
                return headersLists.stream().map(hl -> helpers.buildHttpMessage(hl, body)).collect(Collectors.toList());

        }


        return Collections.singletonList(helpers.buildHttpMessage(headers, body));
    }

    private List<byte[]> removeHeaderByValue(byte[] request) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        byte[] body = Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length);
        List<String> headers = new ArrayList<>();
        switch (which) {
            case REPLACE_FIRST:
                AtomicInteger index = new AtomicInteger(0);
                headers = analyzedRequest.getHeaders().stream().filter(h -> !(matches(h.split(":")[1]) &&
                        index.getAndIncrement() < 1)).collect(Collectors.toList());
                break;
            case REPLACE_ALL:
                headers = analyzedRequest.getHeaders().stream()
                        .filter(h -> !(matches(h.split(":")[1]))).collect(Collectors.toList());
                break;
            case REPLACE_ALL_POSSIBILITIES:
                List<List<String>> headersLists = new ArrayList<>();
                for (ListIterator<String> it = analyzedRequest.getHeaders().listIterator(); it.hasNext(); ) {
                    String header = it.next();
                    if (matches(header.split(":")[1])) {
                        it.remove();
                        List<String> newList = new ArrayList<>(analyzedRequest.getHeaders().size());
                        Collections.copy(newList, analyzedRequest.getHeaders());
                        headersLists.add(newList);
                    }
                }
                if (headersLists.isEmpty()) headersLists.add(analyzedRequest.getHeaders());
                return headersLists.stream().map(hl -> helpers.buildHttpMessage(hl, body)).collect(Collectors.toList());

        }

        return Collections.singletonList(helpers.buildHttpMessage(headers, body));
    }


    private List<byte[]> updateCookieValueByName(byte[] request) {
        return updateBurpParam(request, IParameter.PARAM_COOKIE,
                MatchAndReplaceType.MATCH_NAME_REPLACE_VALUE);
    }

    private List<byte[]> updateRequestFirstLine(byte[] request) {
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        List<String> headers = analyzedRequest.getHeaders();
        byte[] body = Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length);
        String firstRequestString = headers.get(0);
        switch (which) {
            case REPLACE_FIRST:
                headers.set(0, firstRequestString.replaceFirst(this.match, this.replace));
                break;
            case REPLACE_ALL:
                headers.set(0, firstRequestString.replaceAll(this.match, this.replace));
                break;
            case REPLACE_ALL_POSSIBILITIES:
                Pattern pattern = Pattern.compile(getMatch());
                Matcher matcher = pattern.matcher(firstRequestString);
                List<ArrayList<Byte>> outputs = new ArrayList<>();

                Utils.replaceRecursive(outputs, firstRequestString.getBytes(StandardCharsets.US_ASCII), matcher, getReplace(), 0);

                List<String> lines = outputs.stream().map(Utils::byteArrayListToByteArray).map(String::new).collect(Collectors.toList());

                return lines.stream().map(l -> {
                    headers.set(0, l);
                    return helpers.buildHttpMessage(headers, body);
                }).collect(Collectors.toList());
        }

        return Collections.singletonList(helpers.buildHttpMessage(headers, body));
    }

    public List<byte[]> performReplacement(IHttpRequestResponse messageInfo) {
        byte[] request = messageInfo.getRequest();
        if (this.isEnabled) {
            switch (this.type) {
                case ("Request Header"):
                    return updateHeader(request);
                case ("Request Body"):
                    return Collections.singletonList(updateRequestBody(request));
                case ("Request Param Name"):
                    return updateRequestParamName(request);
                case ("Request Param Value"):
                    return updateRequestParamValue(request);
                case ("Request Cookie Name"):
                    return updateCookieName(request);
                case ("Request Cookie Value"):
                    return updateCookieValue(request);
                case ("Request First Line"):
                    return updateRequestFirstLine(request);
                case ("Request String"):
                    return updateContent(request);
                case ("Add Header"):
                    return addHeader(request);
                case ("Remove Parameter By Name"):
                    return removeParameterByName(request);
                case ("Remove Parameter By Value"):
                    return removeParameterByValue(request);
                case ("Remove Cookie By Name"):
                    return removeCookieByName(request);
                case ("Remove Cookie By Value"):
                    return removeCookieByValue(request);
                case ("Remove Header By Name"):
                    return removeHeaderByName(request);
                case ("Remove Header By Value"):
                    return removeHeaderByValue(request);
                case ("Match Param Name, Replace Value"):
                    return updateRequestParamValueByName(request);
                case ("Match Cookie Name, Replace Value"):
                    return updateCookieValueByName(request);
                case ("Match Header Name, Replace Value"):
                    return matchHeaderNameUpdateValue(request);
                default:
                    return Collections.singletonList(request);
            }
        }
        return Collections.singletonList(request);
    }

    public String getType() {
        return type;
    }

    public String getMatch() {
        return match;
    }

    public String getReplace() {
        return replace;
    }

    public String getComment() {
        return comment;
    }

    public boolean isRegexMatch() {
        return isRegexMatch;
    }

    public boolean isEnabled() {
        return isEnabled;
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setMatch(String match) {
        this.match = match;
    }

    public void setReplace(String replace) {
        this.replace = replace;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public void setRegexMatch(Boolean regexMatch) {
        isRegexMatch = regexMatch;
    }

    public void setEnabled(Boolean enabled) {
        isEnabled = enabled;
    }

    public String getWhich() {
        return ReplacementCountOption.valueOf(which);
    }

    public void setWhich(String which) {
        this.which = ReplacementCountOption.byValue(which);
    }

    public Boolean getRegexMatch() {
        return isRegexMatch;
    }

    public Boolean getEnabled() {
        return isEnabled;
    }


}
