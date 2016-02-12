/*******************************************************************************
 *                                                                              
 *  Copyright FUJITSU LIMITED 2016                                             
 *                                                                              
 *  Author: brandstetter                                                     
 *                                                                              
 *  Creation Date: 07.10.2011                                                      
 *                                                                              
 *  Completion Time: 07.10.2011                                              
 *                                                                              
 *******************************************************************************/

package org.oscm.domobjects;

import java.util.List;
import java.util.concurrent.Callable;

import javax.ejb.EJBException;

import org.junit.Assert;
import org.junit.Test;

import org.oscm.domobjects.enums.ModificationType;
import org.oscm.test.data.Organizations;
import org.oscm.test.data.Products;
import org.oscm.test.data.TechnicalProducts;
import org.oscm.internal.types.enumtypes.OrganizationRoleType;
import org.oscm.internal.types.enumtypes.ServiceAccessType;
import org.oscm.internal.types.exception.NonUniqueBusinessKeyException;
import org.oscm.internal.types.exception.ObjectNotFoundException;

/**
 * @author brandstetter
 * 
 */
public class ProductToPaymentTypeIT extends DomainObjectTestBase {

    private Product prod;
    private ProductToPaymentType prodToPt;
    private PaymentType ptCreditCard;
    private PaymentType ptDirectDebit;

    @Override
    protected void dataSetup() throws Exception {

        // PaymentTypes are created in the DomainObjectTest::setup
        createOrganizationRoles(mgr);

        Organization techProv = Organizations.createOrganization(mgr,
                OrganizationRoleType.TECHNOLOGY_PROVIDER);
        Organization supplier = Organizations.createOrganization(mgr,
                OrganizationRoleType.SUPPLIER);

        TechnicalProduct techProd = TechnicalProducts.createTechnicalProduct(
                mgr, techProv, "techProv_ID", false, ServiceAccessType.LOGIN);
        mgr.persist(techProd);

        prod = Products.createProductWithoutPriceModel(supplier, techProd,
                "product_ID");
        mgr.persist(prod);

        ptDirectDebit = findPaymentType(DIRECT_DEBIT, mgr);
        prodToPt = new ProductToPaymentType(prod, ptDirectDebit);
        mgr.persist(prodToPt);
    }

    @Test
    public void testAdd() throws Exception {
        try {
            runTX(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    doTestAdd();
                    return null;
                }
            });

            runTX(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    doTestAddCheck();
                    return null;
                }
            });
        } catch (EJBException e) {
            throw e.getCausedByException();
        }
    }

    @Test(expected = NonUniqueBusinessKeyException.class)
    public void testAdd_Duplicate() throws Exception {
        try {
            runTX(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    doTestAdd();
                    return null;
                }
            });

            runTX(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    doTestAdd();
                    return null;
                }
            });
        } catch (EJBException e) {
            throw e.getCausedByException();
        }
    }

    @Test
    public void testModify() throws Exception {
        try {
            runTX(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    doTestAdd();
                    return null;
                }
            });
            final PaymentType newPt = runTX(new Callable<PaymentType>() {
                @Override
                public PaymentType call() throws Exception {
                    ProductToPaymentType ref = mgr.getReference(
                            ProductToPaymentType.class, prodToPt.getKey());
                    PaymentType pt = findPaymentType(INVOICE, mgr);
                    ref.setPaymentType(pt);
                    mgr.persist(ref);
                    return pt;
                }
            });

            runTX(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    doTestModifyCheck(newPt);
                    return null;
                }
            });
        } catch (EJBException e) {
            throw e.getCausedByException();
        }
    }

    @Test
    public void testDelete() throws Exception {
        try {
            runTX(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    doTestAdd();
                    return null;
                }
            });
            runTX(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    ProductToPaymentType ref = mgr.getReference(
                            ProductToPaymentType.class, prodToPt.getKey());
                    mgr.remove(ref);
                    return null;
                }
            });
            runTX(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    doTestDeleteCheck();
                    return null;
                }
            });
        } catch (EJBException e) {
            throw e.getCausedByException();
        }
    }

    protected void doTestDeleteCheck() throws ObjectNotFoundException {
        Assert.assertNull(mgr.find(ProductToPaymentType.class,
                prodToPt.getKey()));

        List<DomainHistoryObject<?>> list = mgr.findHistory(prodToPt);
        Assert.assertNotNull(list);
        Assert.assertEquals(2, list.size());

        ProductToPaymentTypeHistory hist = ProductToPaymentTypeHistory.class
                .cast(list.get(1));
        Assert.assertEquals(prod.getKey(), hist.getProductObjKey());
        Assert.assertEquals(ptCreditCard.getKey(), hist.getPaymentTypeObjKey());
        Assert.assertEquals(prodToPt.getKey(), hist.getObjKey());
        Assert.assertEquals(1, hist.getObjVersion());
        Assert.assertEquals(ModificationType.DELETE, hist.getModtype());
        Assert.assertEquals("guest", hist.getModuser());

        Product prodDb = mgr.getReference(Product.class, prod.getKey());

        List<ProductToPaymentType> ptList = prodDb.getPaymentTypes();
        Assert.assertNotNull(ptList);
        Assert.assertEquals(1, ptList.size());

    }

    protected void doTestAdd() throws Exception {
        prod = mgr.getReference(Product.class, prod.getKey());
        ptCreditCard = findPaymentType(CREDIT_CARD, mgr);

        prodToPt = new ProductToPaymentType(prod, ptCreditCard);
        mgr.persist(prodToPt);
    }

    protected void doTestAddCheck() throws Exception {
        ProductToPaymentType ref = mgr.getReference(ProductToPaymentType.class,
                prodToPt.getKey());
        Assert.assertEquals(prod.getKey(), ref.getProduct().getKey());
        Assert.assertEquals(ptCreditCard.getKey(), ref.getPaymentType()
                .getKey());
        Assert.assertEquals(0, ref.getVersion());

        List<DomainHistoryObject<?>> list = mgr.findHistory(ref);
        Assert.assertNotNull(list);
        Assert.assertEquals(1, list.size());

        ProductToPaymentTypeHistory hist = ProductToPaymentTypeHistory.class
                .cast(list.get(0));
        Assert.assertEquals(prod.getKey(), hist.getProductObjKey());
        Assert.assertEquals(ptCreditCard.getKey(), hist.getPaymentTypeObjKey());
        Assert.assertEquals(ref.getKey(), hist.getObjKey());
        Assert.assertEquals(0, hist.getObjVersion());
        Assert.assertEquals(ModificationType.ADD, hist.getModtype());
        Assert.assertEquals("guest", hist.getModuser());

        Product prodDb = mgr.getReference(Product.class, prod.getKey());

        List<ProductToPaymentType> ptList = prodDb.getPaymentTypes();
        Assert.assertNotNull(ptList);
        Assert.assertEquals(2, ptList.size());
        Assert.assertTrue(ptList.contains(prodToPt));
    }

    protected void doTestModifyCheck(PaymentType newPt) throws Exception {
        ProductToPaymentType ref = mgr.getReference(ProductToPaymentType.class,
                prodToPt.getKey());
        Assert.assertEquals(newPt.getKey(), ref.getPaymentType().getKey());
        Assert.assertEquals(prod.getKey(), ref.getProduct().getKey());
        Assert.assertEquals(1, ref.getVersion());
        Assert.assertEquals("INVOICE", ref.getPaymentType().getPaymentTypeId());

        List<DomainHistoryObject<?>> list = mgr.findHistory(ref);
        Assert.assertNotNull(list);
        Assert.assertEquals(2, list.size());

        ProductToPaymentTypeHistory hist = ProductToPaymentTypeHistory.class
                .cast(list.get(1));
        Assert.assertEquals(newPt.getKey(), hist.getPaymentTypeObjKey());
        Assert.assertEquals(prod.getKey(), hist.getProductObjKey());
        Assert.assertEquals(ref.getKey(), hist.getObjKey());
        Assert.assertEquals(1, hist.getObjVersion());
        Assert.assertEquals(ModificationType.MODIFY, hist.getModtype());
        Assert.assertEquals("guest", hist.getModuser());

        Product prodDb = mgr.getReference(Product.class, prod.getKey());

        List<ProductToPaymentType> ptList = prodDb.getPaymentTypes();
        Assert.assertNotNull(ptList);
        Assert.assertEquals(2, ptList.size());
        Assert.assertTrue(ptList.contains(prodToPt));
    }

}
