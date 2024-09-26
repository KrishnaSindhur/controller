/*
Copyright 2024 krishna.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	certsv1 "github.com/KrishnaSindhur/certificate-manager.git/api/v1"
)

var _ = Describe("Certificate Controller", func() {
	Context("When reconciling a Certificate resource", func() {
		const resourceName = "test-certificate"
		const secretName = "test-certificate-secret"
		const dnsName = "example.com"
		namespace := "default"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: namespace,
		}

		BeforeEach(func() {
			By("creating a Certificate custom resource")
			certificate := &certsv1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: certsv1.CertificateSpec{
					DnsName: dnsName,
					SecretRef: certsv1.SecretReference{
						Name: secretName,
					},
				},
			}

			err := k8sClient.Get(ctx, typeNamespacedName, certificate)
			if err != nil && errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, certificate)).To(Succeed())
			}
		})

		AfterEach(func() {
			By("Cleaning up the created Certificate resource")
			resource := &certsv1.Certificate{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())

			By("Cleaning up the Secret created by the Certificate controller")
			secret := &corev1.Secret{}
			secretNamespacedName := types.NamespacedName{
				Name:      secretName,
				Namespace: namespace,
			}
			err = k8sClient.Get(ctx, secretNamespacedName, secret)
			if err == nil {
				Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			}
		})

		It("should successfully reconcile and create the Secret", func() {
			By("Reconciling the created Certificate resource")
			controllerReconciler := &CertificateReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying that the Secret was created")
			secret := &corev1.Secret{}
			secretNamespacedName := types.NamespacedName{
				Name:      secretName,
				Namespace: namespace,
			}
			err = k8sClient.Get(ctx, secretNamespacedName, secret)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Data).To(HaveKey("tls.crt"))
			Expect(secret.Data).To(HaveKey("tls.key"))
		})

		It("should update the Secret if it already exists", func() {
			By("Creating a Secret manually")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"tls.crt": []byte("dummy-cert"),
					"tls.key": []byte("dummy-key"),
				},
				Type: corev1.SecretTypeTLS,
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Reconciling the Certificate resource again")
			controllerReconciler := &CertificateReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying that the Secret was updated")
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      secretName,
				Namespace: namespace,
			}, secret)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Data["tls.crt"]).NotTo(Equal([]byte("dummy-cert")))
			Expect(secret.Data["tls.key"]).NotTo(Equal([]byte("dummy-key")))
		})
	})
})
