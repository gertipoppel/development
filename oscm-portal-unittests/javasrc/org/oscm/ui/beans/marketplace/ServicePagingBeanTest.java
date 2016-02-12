/*******************************************************************************
 *                                                                              
 *  Copyright FUJITSU LIMITED 2016                                             
 *                                                                              
 *  Author: Dirk Bernsau
 *                                                                              
 *  Creation Date: May 6, 2011                                                      
 *                                                                              
 *  Completion Time: May 6, 2011                                              
 *                                                                              
 *******************************************************************************/

package org.oscm.ui.beans.marketplace;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.Assert;

import org.junit.Before;
import org.junit.Test;

import org.oscm.ui.beans.MarketplaceConfigurationBean;
import org.oscm.ui.model.MarketplaceConfiguration;
import org.oscm.internal.types.enumtypes.Sorting;

/**
 * @author Dirk Bernsau
 * 
 */
public class ServicePagingBeanTest {

    private ServicePagingBean bean;
    private MarketplaceConfiguration config;

    @Before
    public void setUp() {
        config = new MarketplaceConfiguration();
        bean = new ServicePagingBean();

        MarketplaceConfigurationBean mcb = mock(MarketplaceConfigurationBean.class);
        when(mcb.getCurrentConfiguration()).thenReturn(config);
        bean.setMarketplaceConfigurationBean(mcb);
    }

    @Test
    public void testDefaultPageSize() {
        assertEquals(10, bean.getPageSize());
    }

    @Test
    public void testChangePageSize() {
        int page = 5;
        bean.setSelectedPage(page);
        assertEquals(page, bean.getSelectedPage());
        bean.setPageSize(bean.getPageSize());
        // no change => keep page
        assertEquals(page, bean.getSelectedPage());
        bean.setPageSize(bean.getPageSize() * 2);
        assertEquals(1, bean.getSelectedPage());
    }

    @Test
    public void testChangeSorting() {
        int page = 5;
        bean.setSorting(Sorting.ACTIVATION_ASCENDING);
        bean.setSelectedPage(page);
        assertEquals(page, bean.getSelectedPage());
        bean.setSorting(Sorting.ACTIVATION_ASCENDING);
        // no change => keep page
        assertEquals(page, bean.getSelectedPage());
        bean.setSorting(Sorting.NAME_DESCENDING);
        assertEquals(1, bean.getSelectedPage());
    }

    /**
     * Sorting by rating must be available with enabled reviews
     */
    @Test
    public void getSortingCriteria() {
        // given - base setup

        // when
        List<String> sorting = bean.getSortingCriteria();

        // then
        Assert.assertTrue(sorting.indexOf(Sorting.ACTIVATION_ASCENDING.name()) == 0);
        Assert.assertTrue(sorting.indexOf(Sorting.ACTIVATION_DESCENDING.name()) == 1);
        Assert.assertTrue(sorting.indexOf(Sorting.NAME_ASCENDING.name()) == 2);
        Assert.assertTrue(sorting.indexOf(Sorting.NAME_DESCENDING.name()) == 3);
        Assert.assertTrue(sorting.indexOf(Sorting.RATING_ASCENDING.name()) == 4);
        Assert.assertTrue(sorting.indexOf(Sorting.RATING_DESCENDING.name()) == 5);
    }

    /**
     * Sorting by rating must not be available with disabled reviews
     */
    @Test
    public void getSortingCriteria_ReviewDisabled() {
        // given
        config.setReviewEnabled(false);

        // when
        List<String> list = bean.getSortingCriteria();

        // then: only 4 criterion available!
        assertEquals(list.size(), 4);
        assertEquals(Sorting.ACTIVATION_ASCENDING.name(), list.get(0));
        assertEquals(Sorting.ACTIVATION_DESCENDING.name(), list.get(1));
        assertEquals(Sorting.NAME_ASCENDING.name(), list.get(2));
        assertEquals(Sorting.NAME_DESCENDING.name(), list.get(3));
    }

    @Test
    public void testChangeFilter() {
        int page = 5;
        bean.setFilterTag("TestTag");
        bean.setSelectedPage(page);
        assertEquals(page, bean.getSelectedPage());
        bean.setFilterTag("TestTag");
        // no change => keep page
        assertEquals(page, bean.getSelectedPage());
        bean.setFilterTag("TestTagX");
        assertEquals(1, bean.getSelectedPage());
    }

    @Test
    public void testResetFilter() {
        int page = 5;
        bean.setFilterTag("TestTag");
        bean.setSelectedPage(page);
        assertEquals(page, bean.getSelectedPage());
        bean.setFilterTag(null);
        assertEquals(1, bean.getSelectedPage());
    }

    @Test
    public void testFilterDisplay() {
        final String tagDisplay = "TestTag";
        final String tag = "en," + tagDisplay;
        bean.setFilterTag(tag);
        assertEquals(tag, bean.getFilterTag());
        assertEquals(tagDisplay, bean.getFilterTagForDisplay());
        bean.setFilterTag(null);
    }

    @Test
    public void testDelete() {
        bean.setPageSize(5);
        bean.setResultSize(11);
        bean.setSelectedPage(3);
        assertEquals(3, bean.getSelectedPage());
        assertEquals(1, bean.getFirstVisiblePage());
        assertEquals(3, bean.getLastVisiblePage());
        assertEquals(11, bean.getLastOnPage());
        assertEquals(11, bean.getFirstOnPage());

        // Simulate a service has been deleted
        bean.setResultSize(10);
        // The before selected page is no more available
        // - ensure we are on the last page
        assertEquals(2, bean.getSelectedPage());
        assertEquals(1, bean.getFirstVisiblePage());
        assertEquals(2, bean.getLastVisiblePage());

        Assert.assertFalse(bean.isNextAvailable());
        Assert.assertTrue(bean.isPreviousAvailable());
        assertEquals(6, bean.getFirstOnPage());
        assertEquals(10, bean.getLastOnPage());
    }

    @Test
    public void testDeleteMany() {
        bean.setPageSize(5);
        bean.setSelectedPage(1);
        bean.setResultSize(11);
        bean.setSelectedPage(3);
        assertEquals(3, bean.getSelectedPage());
        assertEquals(1, bean.getFirstVisiblePage());
        assertEquals(3, bean.getLastVisiblePage());
        // Now, all services except for one have been deleted
        bean.setResultSize(1);
        assertEquals(1, bean.getSelectedPage());
        assertEquals(1, bean.getFirstVisiblePage());
        assertEquals(1, bean.getLastVisiblePage());
        Assert.assertFalse(bean.isNextAvailable());
        Assert.assertFalse(bean.isPreviousAvailable());
    }

    @Test
    public void testInsert() {
        bean.setPageSize(5);
        bean.setResultSize(10);
        bean.setSelectedPage(2);
        Assert.assertFalse(bean.isNextAvailable());
        Assert.assertTrue(bean.isPreviousAvailable());
        bean.setResultSize(11);
        assertEquals(2, bean.getSelectedPage());
        Assert.assertTrue(bean.isNextAvailable());
        Assert.assertTrue(bean.isPreviousAvailable());
    }

    @Test
    public void testSingleService() {
        bean.setResultSize(1);
        assertEquals(1, bean.getFirstVisiblePage());
        assertEquals(1, bean.getLastVisiblePage());

        Assert.assertFalse(bean.isNextAvailable());
        Assert.assertFalse(bean.isPreviousAvailable());
    }

    @Test
    public void testNoResult() {
        bean.setResultSize(-1);
        assertEquals(1, bean.getFirstVisiblePage());
        assertEquals(1, bean.getLastVisiblePage());
        // No next and previous
        Assert.assertFalse(bean.isNextAvailable());
        Assert.assertFalse(bean.isPreviousAvailable());
    }

    @Test
    public void testNextAndPrevious() {
        bean.setResultSize(11);
        bean.setPageSize(10);
        assertEquals(1, bean.getSelectedPage());
        Assert.assertTrue(bean.isNextAvailable());
        Assert.assertFalse(bean.isPreviousAvailable());
        bean.setSelectedPage(2);
        assertEquals(2, bean.getSelectedPage());
    }

    @Test
    public void testSearch() {
        bean.setSearchPhrase("Test");
        bean.setSearchPhrase(" Test");

        Assert.assertTrue(bean.isNewSearchRequired());
        bean.setSearchPhrase("Test");
        bean.setSearchPhrase("test");
        Assert.assertTrue(bean.isNewSearchRequired());
        bean.setSearchPhrase("test test");
        Assert.assertTrue(bean.isNewSearchRequired());
        bean.resetNewSearchRequired();
        Assert.assertFalse(bean.isNewSearchRequired());
        bean.setSearchPhrase("test test");
        Assert.assertTrue(bean.isNewSearchRequired());

        // Test limits
        Assert.assertEquals(bean.getSearchResultSizeLimit(), 100);
        Assert.assertEquals(bean.getMaxLengthSearchPhrase(), 255);
    }

    @Test
    public void isFilterTagSelected_notSet() {
        // given
        bean.setFilterTag(null);

        // when
        boolean tagSelected = bean.isFilterTagSelected();

        // then
        Assert.assertFalse(tagSelected);
    }

    @Test
    public void isFilterTagSelected_emptyString() {
        // given
        bean.setFilterTag(" ");

        // when
        boolean tagSelected = bean.isFilterTagSelected();

        // then
        Assert.assertFalse(tagSelected);
    }

    @Test
    public void isFilterTagSelected() {
        // given
        bean.setFilterTag("aTag");

        // when
        boolean tagSelected = bean.isFilterTagSelected();

        // then
        Assert.assertTrue(tagSelected);
    }
    
    @Test
    public void isFilterTagSelected_bug9695() {

        bean.setFilterTag("filterTag");
        bean.setFilterCategoryForDisplay("");
        bean.setResultSize(15);

        assertEquals("filterTag : ", bean.getHeaderPrefixForSelectedFilter());
        assertEquals("marketplace.servicesList.headerMultipleServices",
                bean.getServiceListHeaderKey());

        bean.setFilterTag("");
        bean.setFilterCategoryForDisplay("");
        bean.setResultSize(1);
        assertEquals("", bean.getHeaderPrefixForSelectedFilter());
        assertEquals("marketplace.servicesList.headerSingleService",
                bean.getServiceListHeaderKey());

        bean.setFilterTag("");
        bean.setFilterCategoryForDisplay("");
        bean.setResultSize(0);
        assertEquals("", bean.getHeaderPrefixForSelectedFilter());
        assertEquals("marketplace.servicesList.headerMultipleServices",
                bean.getServiceListHeaderKey());
    }

    @Test
    public void isSearchServiceRequest_bug9695() {
        // Search services in marketplace and login lead to operation failed.
        bean.setFilterTag("");
        bean.setFilterCategoryForDisplay(null);
        bean.setResultSize(0);
        assertEquals("", bean.getFilterCategoryForDisplay());
        assertEquals("", bean.getHeaderPrefixForSelectedFilter());
        assertEquals("marketplace.servicesList.headerMultipleServices",
                bean.getServiceListHeaderKey());

    }

}
