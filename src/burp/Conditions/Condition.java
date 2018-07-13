package burp.Conditions;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.google.common.io.Files;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class Condition {

  private String booleanOperator;
  private String matchType;
  private String matchRelationship;
  private String matchCondition;
  private boolean isEnabled;

  public Condition(
      String booleanOperator,
      String matchType,
      String matchRelationship,
      String matchCondition) {
    setEnabled(true);
    setBooleanOperator(booleanOperator);
    setMatchType(matchType);
    setMatchRelationship(matchRelationship);
    setMatchCondition(matchCondition);
  }

  public Condition(
      String booleanOperator,
      String matchType,
      String matchRelationship,
      String matchCondition,
      boolean isEnabled) {
    setEnabled(isEnabled);
    setBooleanOperator(booleanOperator);
    setMatchType(matchType);
    setMatchRelationship(matchRelationship);
    setMatchCondition(matchCondition);
  }

  public static final String[] BOOLEAN_OPERATOR_OPTIONS = {
      "And",
      "Or"
  };

  public static final String[] MATCH_TYPE_OPTIONS = {
      "Domain Name",
      //"IP Address",
      "Protocol",
      "HTTP Method",
      "URL",
      "File Extension",
      "Request",
      "Cookie Name",
      "Cookie Value",
      "Any Header",
      "Request Body",
      "Param Name",
      "Param Value",
      "Sent From Tool",
      "Listener Port"
  };

  public static String[] getMatchRelationshipOptions(String inputString) {
    switch (inputString) {
      case "Domain Name":
        return new String[]{"Matches", "Does Not Match"};
      case "IP Address":
        return new String[]{"Is In Range", "Is Not In Range"};
      case "Protocol":
        return new String[]{"Is HTTP", "Is Not HTTP"};
      case "HTTP Method":
        return new String[]{"Matches", "Does Not Match"};
      case "URL":
        return new String[]{"Matches", "Does Not Match", "Is In Scope"};
      case "File Extension":
        return new String[]{"Matches", "Does Not Match"};
      case "Request":
        return new String[]{"Contains Parameters", "Does Not Contain Parameters"};
      case "Cookie Name":
        return new String[]{"Matches", "Does Not Match"};
      case "Cookie Value":
        return new String[]{"Matches", "Does Not Match"};
      case "Any Header":
        return new String[]{"Matches", "Does Not Match"};
      case "Request Body":
        return new String[]{"Matches", "Does Not Match"};
      case "Param Name":
        return new String[]{"Matches", "Does Not Match"};
      case "Param Value":
        return new String[]{"Matches", "Does Not Match"};
      case "Sent From Tool":
        return new String[]{
            "Burp",
            "Proxy",
            "Repeater",
            "Spider",
            "Intruder",
            "Scanner"
        };
      case "Listener Port":
        return new String[]{"Matches", "Does Not Match"};
      default:
        throw new IllegalStateException("getMatchRelationshipOptions() not defined for "+inputString);
    }
  }

  public static boolean matchConditionIsEditable(String inputString) {
    switch (inputString) {
      case "Domain Name":
        return true;
      case "IP Address":
        return true;
      case "Protocol":
        return false;
      case "HTTP Method":
        return true;
      case "URL":
        return true;
      case "File Extension":
        return true;
      case "Request":
        return false;
      case "Cookie Name":
        return true;
      case "Cookie Value":
        return true;
      case "Any Header":
        return true;
      case "Request Body":
        return true;
      case "Param Name":
        return true;
      case "Param Value":
        return true;
      case "Sent From Tool":
        return false;
      case "Listener Port":
        return true;
      default:
        throw new IllegalStateException("matchConditionIsEditable() not defined for input "+inputString);
    }
  }

  private boolean checkDomainName(IHttpRequestResponse messageInfo) {
    switch (this.matchRelationship) {
      case "Matches":
        return messageInfo.getHttpService().getHost().equals(this.matchCondition);
      default:
        return !messageInfo.getHttpService().getHost().equals(this.matchCondition);
    }
  }

  private boolean checkProtocol(IHttpRequestResponse messageInfo) {
    String protocol = messageInfo.getHttpService().getProtocol();
    switch (this.matchRelationship) {
      case "Is HTTP":
        return protocol.equals("http");
      default:
        return !protocol.equals("http");
    }
  }

  private boolean checkHttpMethod(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    switch (this.matchRelationship) {
      case "Matches":
        return analyzedRequest.getMethod().matches(this.matchCondition);
      default:
        return !analyzedRequest.getMethod().matches(this.matchCondition);
    }
  }

  private boolean checkUrl(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    switch (this.matchRelationship) {
      case "Is In Scope":
        return BurpExtender.getCallbacks().isInScope(analyzedRequest.getUrl());
      case "Matches":
        return analyzedRequest.getUrl().toString().matches(this.matchCondition);
      default:
        return !analyzedRequest.getUrl().toString().matches(this.matchCondition);
    }
  }

  private boolean checkFileExtension(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    String fileExtension = Files.getFileExtension(analyzedRequest.getUrl().toString());
    switch (this.matchRelationship) {
      case "Matches":
        return fileExtension.matches(this.matchCondition);
      default:
        return !fileExtension.matches(this.matchCondition);
    }
  }

  private boolean checkRequest(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    long parameterCount = analyzedRequest.getParameters()
        .stream()
        .filter(
            p -> p.getType() == IParameter.PARAM_URL || p.getType() == IParameter.PARAM_BODY)
        .count();
    switch (this.matchRelationship) {
      case "Contains Parameters":
        return parameterCount > 0;
      default:
        return !(parameterCount > 0);
    }
  }

  private boolean checkCookieName(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    List<IParameter> cookiesByName = analyzedRequest.getParameters()
        .stream()
        .filter(p -> p.getType() == IParameter.PARAM_COOKIE)
        .filter(p -> p.getName().matches(this.matchCondition))
        .collect(Collectors.toList());
    switch (this.matchRelationship) {
      case "Matches":
        return cookiesByName.size() > 0;
      default:
        return !(cookiesByName.size() > 0);
    }
  }

  private boolean checkCookieValue(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    List<IParameter> cookiesByName = analyzedRequest.getParameters()
        .stream()
        .filter(p -> p.getType() == IParameter.PARAM_COOKIE)
        .filter(p -> p.getName().matches(this.matchCondition))
        .collect(Collectors.toList());
    switch (this.matchRelationship) {
      case "Matches":
        return cookiesByName.size() > 0;
      default:
        return !(cookiesByName.size() > 0);
    }
  }

  private boolean checkAnyHeader(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    List<String> matchingHeaders = analyzedRequest.getHeaders()
        .stream()
        .filter(h -> h.matches(this.matchCondition))
        .collect(Collectors.toList());
    switch (this.matchRelationship) {
      case "Matches":
        return matchingHeaders.size() > 0;
      default:
        return !(matchingHeaders.size() > 0);
    }
  }

  private boolean checkRequestBody(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    byte[] request = messageInfo.getRequest();
    String bodyString = new String(
        Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length));
    switch (this.matchRelationship) {
      case ("Matches"):
        return bodyString.matches(this.matchCondition);
      default:
        return !bodyString.matches(this.matchCondition);
    }
  }

  private boolean checkParamName(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    List<IParameter> parametersByName = analyzedRequest.getParameters()
        .stream()
        .filter(p -> p.getName().matches(this.matchCondition))
        .collect(Collectors.toList());
    switch (this.matchRelationship) {
      case "Matches":
        return parametersByName.size() > 0;
      default:
        return !(parametersByName.size() > 0);
    }
  }

  private boolean checkParamValue(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    List<IParameter> parametersByValue = analyzedRequest.getParameters()
        .stream()
        .filter(p -> p.getValue().matches(this.matchCondition))
        .collect(Collectors.toList());
    switch (this.matchRelationship) {
      case "Matches":
        return parametersByValue.size() > 0;
      default:
        return !(parametersByValue.size() > 0);
    }
  }

  private boolean checkSentFromTool(int toolFlag) {
    switch (this.matchRelationship) {
      case "Burp":
        return toolFlag != BurpExtender.getCallbacks().TOOL_EXTENDER &&
            toolFlag != BurpExtender.getCallbacks().TOOL_SCANNER;
      case "Proxy":
        return toolFlag == BurpExtender.getCallbacks().TOOL_PROXY;
      case "Repeater":
        return toolFlag == BurpExtender.getCallbacks().TOOL_REPEATER;
      case "Spider":
        return toolFlag == BurpExtender.getCallbacks().TOOL_SPIDER;
      case "Intruder":
        return toolFlag == BurpExtender.getCallbacks().TOOL_INTRUDER;
      default:
        return toolFlag == BurpExtender.getCallbacks().TOOL_SCANNER;
    }
  }

  private boolean checkListenerPort(IHttpRequestResponse messageInfo) {
    if (this.matchType.equals("Matches")) {
      return messageInfo.getHttpService().getPort() == Integer.parseInt(this.matchCondition);
    } else {
      return !(messageInfo.getHttpService().getPort() == Integer.parseInt(this.matchCondition));
    }
  }

  public boolean checkCondition(int toolFlag, IHttpRequestResponse messageInfo) {
    switch (this.matchType) {
      case "Domain Name": return checkDomainName(messageInfo);
      case "Protocol": return checkProtocol(messageInfo);
      case "HTTP Method": return checkHttpMethod(messageInfo);
      case "URL": return checkUrl(messageInfo);
      case "File Extension": return checkFileExtension(messageInfo);
      case "Request": return checkRequest(messageInfo);
      case "Cookie Name": return checkCookieName(messageInfo);
      case "Cookie Value": return checkCookieValue(messageInfo);
      case "Any Header": return checkAnyHeader(messageInfo);
      case "Request Body": return checkRequestBody(messageInfo);
      case "Param Name": return checkParamName(messageInfo);
      case "Param Value": return checkParamValue(messageInfo);
      case "Sent From Tool": return checkSentFromTool(toolFlag);
      case "Listener Port": return checkListenerPort(messageInfo);
      default: throw new IllegalStateException("checkCondition() not defined for the input.");
    }
  }

  public String getBooleanOperator() {
    return booleanOperator;
  }

  public void setBooleanOperator(String booleanOperator) {
    if(Arrays.stream(BOOLEAN_OPERATOR_OPTIONS).anyMatch(s -> s.equals(booleanOperator))) {
      this.booleanOperator = booleanOperator;
    } else if (booleanOperator.equals("")) {
      this.booleanOperator = booleanOperator;
    } else {
      this.booleanOperator = BOOLEAN_OPERATOR_OPTIONS[0];
    }
  }

  public String getMatchType() {
    return matchType;
  }

  public void setMatchType(String matchType) {
    if(Arrays.stream(MATCH_TYPE_OPTIONS).anyMatch(s -> s.equals(matchType))) {
      this.matchType = matchType;
    } else {
      this.matchType = MATCH_TYPE_OPTIONS[0];
    }
  }

  public String getMatchRelationship() {
    return matchRelationship;
  }

  public void setMatchRelationship(String matchRelationship) {
    this.matchRelationship = matchRelationship;
  }

  public String getMatchCondition() {
    return matchCondition;
  }

  public void setMatchCondition(String matchCondition) {
    this.matchCondition = matchCondition;
  }

  public boolean isEnabled() {
    return isEnabled;
  }

  public void setEnabled(boolean enabled) {
    isEnabled = enabled;
  }

}
