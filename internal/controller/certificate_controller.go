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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	certsv1 "github.com/KrishnaSindhur/certificate-manager.git/api/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// CertificateReconciler reconciles a Certificate object
type CertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=certs.certifcate-manager,resources=certificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certs.certifcate-manager,resources=certificates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certs.certifcate-manager,resources=certificates/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the Certificate object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/reconcile

func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the Certificate instance
	cert := &certsv1.Certificate{}
	if err := r.Get(ctx, req.NamespacedName, cert); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// If certificate already issued, skip
	if cert.Status.Issued {
		logger.Info("Certificate already issued")
		return ctrl.Result{}, nil
	}

	// Generate the certificate and private key
	certPEM, keyPEM, err := generateSelfSignedCert(cert.Spec.DnsName)
	if err != nil {
		logger.Error(err, "Failed to generate certificate")
		return ctrl.Result{}, err
	}

	secret := &corev1.Secret{}
	err = r.Client.Get(ctx, client.ObjectKey{
		Name:      cert.Spec.SecretRef.Name,
		Namespace: req.Namespace,
	}, secret)

	if err != nil && errors.IsNotFound(err) {
		// Secret does not exist, create it
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cert.Spec.SecretRef.Name,
				Namespace: req.Namespace,
			},
			Data: map[string][]byte{
				"tls.crt": certPEM,
				"tls.key": keyPEM,
			},
			Type: corev1.SecretTypeTLS,
		}

		if err := r.Client.Create(ctx, secret); err != nil {
			logger.Error(err, "Failed to create Secret")
			return ctrl.Result{}, err
		}
		logger.Info("Secret created", "Secret.Name", cert.Spec.SecretRef.Name)
	} else if err == nil {
		// Secret exists, update it
		secret.Data["tls.crt"] = certPEM
		secret.Data["tls.key"] = keyPEM

		if err := r.Client.Update(ctx, secret); err != nil {
			logger.Error(err, "Failed to update Secret")
			return ctrl.Result{}, err
		}
		logger.Info("Secret updated", "Secret.Name", cert.Spec.SecretRef.Name)
	} else {
		// Some other error occurred
		logger.Error(err, "Failed to get Secret")
		return ctrl.Result{}, err
	}

	// Update Certificate status
	cert.Status.Issued = true
	if err := r.Status().Update(ctx, cert); err != nil {
		logger.Error(err, "Failed to update Certificate status")
		return ctrl.Result{}, err
	}

	logger.Info("Certificate created successfully", "DNS", cert.Spec.DnsName)
	return ctrl.Result{}, nil
}

func generateSelfSignedCert(dnsName string) ([]byte, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 1, 0),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	return certPEM, keyPEM, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certsv1.Certificate{}).
		Complete(r)
}
