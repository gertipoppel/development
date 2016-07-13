/*******************************************************************************
 *                                                                              
 *  Copyright FUJITSU LIMITED 2016                                             
 *                                                                                                                                 
 *  Creation Date: Jun 15, 2016                                                      
 *                                                                              
 *******************************************************************************/

package org.oscm.ui.filter;

import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Test;

import org.oscm.internal.intf.IdentityService;
import org.oscm.internal.intf.MarketplaceService;
import org.oscm.internal.vo.VOMarketplace;
import org.oscm.internal.vo.VOUserDetails;
import org.oscm.types.constants.marketplace.Marketplace;
import org.oscm.ui.beans.BaseBean;
import org.oscm.ui.common.Constants;

public class ClosedMarketplaceFilterTest {
    
    private HttpServletRequest requestMock;
    private HttpServletResponse responseMock;
    private FilterChain chainMock;
    private HttpSession sessionMock;
    private RequestRedirector redirectorMock;
    private ClosedMarketplaceFilter closedMplFilter;
    private MarketplaceService marketplaceService;
    private IdentityService identityService;
    private final static String EXCLUDE_URL_PATTERN = "(.*/a4j/.*|.*/img/.*|.*/css/.*|.*/fonts/.*|.*/scripts/.*|.*/faq/.*|^/slogout.jsf|^/public/.*|^/marketplace/terms/.*|.*/marketplace/img/.*)";
    private static final String INSUFFICIENT_AUTH_URL = Marketplace.MARKETPLACE_ROOT + Constants.INSUFFICIENT_AUTHORITIES_URI;
    private static final String MPL_START_URL = BaseBean.MARKETPLACE_START_SITE;
    private static final String samlSpRedirectPage = "/saml2/redirectToIdp.jsf";
    
    @Before
    public void setup() throws Exception {

        requestMock = mock(HttpServletRequest.class);
        responseMock = mock(HttpServletResponse.class);
        chainMock = mock(FilterChain.class);
        sessionMock = mock(HttpSession.class);
        redirectorMock = mock(RequestRedirector.class);
        doReturn(sessionMock).when(requestMock).getSession();
        marketplaceService = mock(MarketplaceService.class);
        identityService = mock(IdentityService.class);
        
        closedMplFilter = spy(new ClosedMarketplaceFilter());
        closedMplFilter.excludeUrlPattern = EXCLUDE_URL_PATTERN;
        closedMplFilter.marketplaceService = marketplaceService;
        closedMplFilter.identityService = identityService;
        closedMplFilter.redirector = redirectorMock;

        doReturn(false).when(closedMplFilter).isSAMLAuthentication();
    }
    
    
    @Test
    public void testDoFilter_requestMatchesExcludePattern() throws Exception{

        //given
        doReturn("/css/style.css").when(requestMock).getServletPath();
        
        //when
        closedMplFilter.doFilter(requestMock, responseMock, chainMock);
        
        //then
        verify(chainMock, times(1)).doFilter(requestMock, responseMock);  
    }

    @Test
    public void testDoFilter_requestMatchesExcludePattern_SAML() throws Exception{
        //given
        // switching to SAML authentication should not change the behaviour in this case
        doReturn(true).when(closedMplFilter).isSAMLAuthentication();
        doReturn("/css/style.css").when(requestMock).getServletPath();

        //when
        closedMplFilter.doFilter(requestMock, responseMock, chainMock);

        //then
        verify(chainMock, times(1)).doFilter(requestMock, responseMock);
    }

    @Test
    public void testDoFilter_emptyMplId() throws Exception{

        //given
        doReturn("/portal/*").when(requestMock).getServletPath();
        doReturn("").when(sessionMock).getAttribute(Constants.REQ_PARAM_MARKETPLACE_ID);
        
        //when
        closedMplFilter.doFilter(requestMock, responseMock, chainMock);
        
        //then
        verify(chainMock, times(1)).doFilter(requestMock, responseMock);  
    }

    @Test
    public void testDoFilter_emptyMplId_SAML() throws Exception{
        // switching to SAML authentication should cause a redirection to the IDP login page
        //given
        doReturn(true).when(closedMplFilter).isSAMLAuthentication();
        doReturn("/portal/*").when(requestMock).getServletPath();
        doReturn("").when(sessionMock).getAttribute(Constants.REQ_PARAM_MARKETPLACE_ID);

        //when
        closedMplFilter.doFilter(requestMock, responseMock, chainMock);

        //then
        verify(redirectorMock, times(1)).forward(eq(requestMock), eq(responseMock), eq(samlSpRedirectPage));
    }
    
    @Test
    public void testDoFilter_notRestrictedMarketplace() throws Exception{

        //given
        doReturn("/portal/*").when(requestMock).getServletPath();
        doReturn("mpid").when(sessionMock).getAttribute(Constants.REQ_PARAM_MARKETPLACE_ID);
        doReturn(getMarketplace("mpid", false, true)).when(marketplaceService).getMarketplaceById(anyString());
        
        //when
        closedMplFilter.doFilter(requestMock, responseMock, chainMock);
        
        //then
        verify(chainMock, times(1)).doFilter(requestMock, responseMock);  
    }
    @Test
    public void testDoFilter_notRestrictedMarketplace_SAML() throws Exception{
        // switching to SAML authentication should not change the behaviour in this case
        //given
        doReturn("/portal/*").when(requestMock).getServletPath();
        doReturn("mpid").when(sessionMock).getAttribute(Constants.REQ_PARAM_MARKETPLACE_ID);
        doReturn(getMarketplace("mpid", false, true)).when(marketplaceService).getMarketplaceById(anyString());

        //when
        closedMplFilter.doFilter(requestMock, responseMock, chainMock);

        //then
        verify(chainMock, times(1)).doFilter(requestMock, responseMock);
    }
    
    @Test
    public void testDoFilter_restrictedMarketplaceWithAccess() throws Exception{
        //given
        doReturn(true).when(closedMplFilter).isSAMLAuthentication();
        doReturn("/portal/*").when(requestMock).getServletPath();
        doReturn("mpid").when(sessionMock).getAttribute(Constants.REQ_PARAM_MARKETPLACE_ID);
        doReturn(getMarketplace("mpid", true, true)).when(marketplaceService).getMarketplaceById(anyString());
        doReturn(getUserDetails("testUser")).when(identityService).getCurrentUserDetailsIfPresent();
        doReturn(true).when(marketplaceService).doesOrganizationHaveAccessMarketplace(anyString(), anyString());
        
        //when
        closedMplFilter.doFilter(requestMock, responseMock, chainMock);
        
        //then
        verify(chainMock, times(1)).doFilter(requestMock, responseMock);  
    }

    @Test
    public void testDoFilter_restrictedMarketplaceWithAccess_SAML() throws Exception{
        // switching to SAML authentication should not change the behaviour in this case
        //given
        doReturn(true).when(closedMplFilter).isSAMLAuthentication();
        doReturn("/portal/*").when(requestMock).getServletPath();
        doReturn("mpid").when(sessionMock).getAttribute(Constants.REQ_PARAM_MARKETPLACE_ID);
        doReturn(getMarketplace("mpid", true, true)).when(marketplaceService).getMarketplaceById(anyString());
        doReturn(getUserDetails("testUser")).when(identityService).getCurrentUserDetailsIfPresent();
        doReturn(true).when(marketplaceService).doesOrganizationHaveAccessMarketplace(anyString(), anyString());

        //when
        closedMplFilter.doFilter(requestMock, responseMock, chainMock);

        //then
        verify(chainMock, times(1)).doFilter(requestMock, responseMock);
    }
    
    @Test
    public void testDoFilter_restrictedMarketplaceWithNoAccess() throws Exception{

        //given
        doReturn("/portal/*").when(requestMock).getServletPath();
        doReturn("mpid").when(sessionMock).getAttribute(Constants.REQ_PARAM_MARKETPLACE_ID);
        doReturn(getMarketplace("mpid", true, true)).when(marketplaceService).getMarketplaceById(anyString());
        doReturn(getUserDetails("testUser")).when(identityService).getCurrentUserDetailsIfPresent();
        doReturn(false).when(marketplaceService).doesOrganizationHaveAccessMarketplace(anyString(), anyString());
        
        //when
        closedMplFilter.doFilter(requestMock, responseMock, chainMock);
        
        //then
        verify(redirectorMock, times(1)).forward(eq(requestMock), eq(responseMock), eq(INSUFFICIENT_AUTH_URL));  
    }

    @Test
    public void testDoFilter_restrictedMarketplaceWithNoAccess_SAML() throws Exception{
        // user already logged in so no change in behaviour with SAML
        //given
        doReturn(true).when(closedMplFilter).isSAMLAuthentication();
        doReturn("/portal/*").when(requestMock).getServletPath();
        doReturn("mpid").when(sessionMock).getAttribute(Constants.REQ_PARAM_MARKETPLACE_ID);
        doReturn(getMarketplace("mpid", true, true)).when(marketplaceService).getMarketplaceById(anyString());
        doReturn(getUserDetails("testUser")).when(identityService).getCurrentUserDetailsIfPresent();
        doReturn(false).when(marketplaceService).doesOrganizationHaveAccessMarketplace(anyString(), anyString());

        //when
        closedMplFilter.doFilter(requestMock, responseMock, chainMock);

        //then
        verify(redirectorMock, times(1)).forward(eq(requestMock), eq(responseMock), eq(INSUFFICIENT_AUTH_URL));
    }

    @Test
    public void testDoFilter_restrictedMarketplaceWithNullUser() throws Exception{

        //given
        doReturn("/portal/*").when(requestMock).getServletPath();
        doReturn("mpid").when(sessionMock).getAttribute(Constants.REQ_PARAM_MARKETPLACE_ID);
        doReturn(getMarketplace("mpid", true, true)).when(marketplaceService).getMarketplaceById(anyString());
        doReturn(null).when(identityService).getCurrentUserDetailsIfPresent();
        
        //when
        closedMplFilter.doFilter(requestMock, responseMock, chainMock);
        
        //then
        verify(redirectorMock, times(1)).forward(eq(requestMock), eq(responseMock), eq(MPL_START_URL));  
    }

    @Test
    public void testDoFilter_restrictedMarketplaceWithNullUser_SAML() throws Exception{
        // user not logged in yet, so forward to SAML login page
        //given
        doReturn(true).when(closedMplFilter).isSAMLAuthentication();
        doReturn("/portal/*").when(requestMock).getServletPath();
        doReturn("mpid").when(sessionMock).getAttribute(Constants.REQ_PARAM_MARKETPLACE_ID);
        doReturn(getMarketplace("mpid", true, true)).when(marketplaceService).getMarketplaceById(anyString());
        doReturn(null).when(identityService).getCurrentUserDetailsIfPresent();

        //when
        closedMplFilter.doFilter(requestMock, responseMock, chainMock);

        //then
        verify(redirectorMock, times(1)).forward(eq(requestMock), eq(responseMock), eq(samlSpRedirectPage));
    }

    private VOMarketplace getMarketplace(String mplId, boolean isRestricted, boolean hasPublicLandingPage){
        VOMarketplace marketplace = new VOMarketplace();
        marketplace.setMarketplaceId(mplId);
        marketplace.setRestricted(isRestricted);
        marketplace.setHasPublicLandingPage(hasPublicLandingPage);
        return marketplace;
    }
    
    private VOUserDetails getUserDetails(String userId){
        VOUserDetails userDetails = new VOUserDetails();
        userDetails.setUserId(userId);
        return userDetails;
    }
}
